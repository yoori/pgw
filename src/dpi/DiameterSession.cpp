#include <arpa/inet.h>

#include <iostream>
#include <optional>

#include <gears/StringManip.hpp>
#include <gears/Rand.hpp>
#include <gears/Time.hpp>

#include "AVPUtils.hpp"

#include "DiameterPacketFiller.hpp"
#include "DiameterSession.hpp"
#include "CerrCallback.hpp"
#include "FunTask.hpp"

namespace dpi
{
  namespace
  {
    std::string
    get_avp_string_value(const Diameter::AVP& avp)
    {
      const auto& avp_data = avp.data();
      ByteArray ba = avp_data.toOctetString();
      return std::string(reinterpret_cast<const char*>(&ba[0]), ba.size());
    }
  }

  // SCTPDiameterSession::ReadResponsesTask
  class SCTPDiameterSession::ReadResponsesTask: public Gears::Task
  {
  public:
    ReadResponsesTask(SCTPDiameterSession* diameter_session)
      throw()
      : diameter_session_(diameter_session)
    {}

    virtual void
    execute() throw()
    {
      diameter_session_->responses_reading_();
    }

  private:
    SCTPDiameterSession* diameter_session_;
  };

  // SCTPDiameterSession impl
  SCTPDiameterSession::SCTPDiameterSession(
    dpi::LoggerPtr logger,
    const DiameterDictionary& diameter_dictionary,
    BaseConnectionPtr connection,
    std::string origin_host,
    std::string origin_realm,
    std::optional<std::string> destination_host,
    std::optional<std::string> destination_realm,
    unsigned long auth_application_id,
    std::string product_name,
    RequestProcessor request_processor,
    const std::vector<std::string>& source_addresses, // source addresses for diameter packet
    std::vector<DiameterPassAttribute> gx_pass_attributes,
    std::vector<DiameterPassAttribute> gy_pass_attributes
    )
    : USE_FILLER_(use_diameter_filler),
      logger_(std::move(logger)),
      diameter_dictionary_(diameter_dictionary),
      connection_(connection),
      origin_host_(std::move(origin_host)),
      origin_realm_(std::move(origin_realm)),
      destination_host_(std::move(destination_host)),
      destination_realm_(std::move(destination_realm)),
      gx_application_id_(16777238),
      gy_application_id_(4),
      product_name_(product_name),
      request_processor_(request_processor),
      gx_pass_attributes_(std::move(gx_pass_attributes)),
      gy_pass_attributes_(std::move(gy_pass_attributes)),
      origin_state_id_(3801248757)
  {
    Gears::ActiveObjectCallback_var callback(new CerrCallback());

    task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 1));
    add_child_object(task_runner_);

    response_process_task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 3));
    add_child_object(response_process_task_runner_);

    task_runner_->enqueue_task(std::make_shared<ReadResponsesTask>(this));

    for (const auto& addr_str : source_addresses)
    {
      source_addresses_.emplace_back(string_to_ipv4_address(addr_str));
    }

    /*
    if (keep_open_connection_)
    {
      try
      {
        connection_holder_ = socket_init_();
      }
      catch(const Gears::Exception&)
      {}
    }
    */

    //session_id_ = origin_host_ + ";" + std::to_string(Gears::safe_rand()) + ";0;" +
    //  std::to_string(Gears::safe_rand());
  }

  SCTPDiameterSession::~SCTPDiameterSession()
  {
    /*
    if (connection_holder_.has_value())
    {
      socket_close_(connection_holder_->socket_fd);
    }
    */
  }

  void
  SCTPDiameterSession::deactivate_object()
  {
    Gears::CompositeActiveObject::deactivate_object();
    connection_->close();
  }

  void
  SCTPDiameterSession::set_logger(dpi::LoggerPtr logger)
  {
    logger_.swap(logger);
  }

  void
  SCTPDiameterSession::set_request_processor(RequestProcessor request_processor)
  {
    request_processor_ = request_processor;
  }

  /*
  void
  SCTPDiameterSession::connect()
  {
    int socket_fd;

    {
      std::unique_lock<std::mutex> guard(send_lock_);
      socket_fd = connection_holder_.has_value() ? connection_holder_->socket_fd : 0;
    }

    if (!is_connected_(socket_fd))
    {
    }
  }
  */

  /*
  bool
  SCTPDiameterSession::is_connected_(int socket_fd)
  {
    if (socket_fd <= 0)
    {
      return false;
    }

    int error_code;
    socklen_t error_code_size = sizeof(error_code);

    if (::getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error_code, &error_code_size) == -1)
    {
      return false;
    }

    return (error_code == 0);
  }
  */

  /*
  void
  SCTPDiameterSession::make_exchange_i_()
  {
    if (!exchange_done_)
    {
      auto exchange_packet = generate_exchange_packet_();
      connection_->lock()->send_packet(exchange_packet);

      std::cout << "DDDD: to read after exchange" << std::endl;
      std::shared_ptr<Diameter::Packet> response = wait_response_();
      std::cout << "DDDD: from read after exchange" << std::endl;

      std::optional<uint32_t> result_code;
      for (int i = 0; i < response->numberOfAVPs(); ++i)
      {
        const Diameter::AVP& avp = response->avp(i);
        if (avp.header().avpCode() == 268) //< Result-Code
        {
          result_code = avp.data().toUnsigned32();
        }
      }

      if (!result_code.has_value())
      {
        throw DiameterError("Prime exchange failed, no Result-Code in response");
      }
      else if(*result_code != 2001)
      {
        std::ostringstream ostr;
        ostr << "Prime exchange failed, Result-Code: " << *result_code;
        throw DiameterError(ostr.str());
      }

      exchange_done_ = true;
    }
  }
  */

  std::tuple<
    std::optional<uint32_t>,
    std::shared_ptr<Diameter::Packet>,
    SCTPDiameterSession::RequestKey>
  SCTPDiameterSession::send_and_read_response_i_(
    SCTPDiameterSession::PacketGenerator packet_generator)
  {
    /*
    {
      connection_->lock()->connect();
      make_exchange_i_();
    }
    */

    //std::cout << "[DIAMETER] send_and_read_response_i_: "
    //  "connection_ = " << connection_.get() <<
    //  ", this = " << this <<
    //  ", RETRY_COUNT_ = " << RETRY_COUNT_ <<
    //  std::endl;

    for (int retry_i = 0; retry_i < RETRY_COUNT_; ++retry_i)
    {
      //connect();

      try
      {
        std::shared_ptr<Diameter::Packet> response;

        //std::cout << "[DIAMETER] To send diameter packet: connection_ = " << connection_.get() <<
        //  ", this = " << this << std::endl;

        auto [request_key, send_packet] = packet_generator();
        connection_->lock()->send_packet(send_packet);
        response = wait_response_(request_key);

        std::cout << "[DIAMETER] From send diameter packet: connection_ = " << connection_.get() <<
          ", this = " << this << std::endl;

        std::optional<uint32_t> result_code;
        for (int i = 0; i < response->numberOfAVPs(); ++i)
        {
          const Diameter::AVP& avp = response->avp(i);
          if (avp.header().avpCode() == 268) //< Result-Code
          {
            result_code = avp.data().toUnsigned32();
          }
        }

        return std::make_tuple(result_code, response, request_key);
      }
      catch(const std::exception& ex)
      {
        if (logger_)
        {
          std::ostringstream ostr;
          ostr << "[DEBUG] Diameter exception: " << ex.what();
          logger_->log(ostr.str());
        }

        if (retry_i == RETRY_COUNT_ - 1)
        {
          throw;
        }
      }
    }

    return std::make_tuple(0, nullptr, RequestKey());
  }

  void
  SCTPDiameterSession::process_input_request_(const Diameter::Packet& request)
  {
    // response to watchdog
    if (request.header().commandCode() == 280) // Command: Device-Watchdog
    {
      std::cout << "[DIAMETER] Send response for Watchdog request" << std::endl;
      // RESPONSE WATCHDOG
      response_process_task_runner_->enqueue_task(std::make_shared<FunTask>(
        [this, request]()
        {
          auto watchdog_packet = generate_watchdog_packet_(
            request.header().hbhIdentifier(),
            request.header().eteIdentifier());
          connection_->lock()->send_packet(watchdog_packet);
        }
      ));
    }
    else
    {
      response_process_task_runner_->enqueue_task(std::make_shared<FunTask>(
        [this, request]()
        {
          request_processor_(request);
        }));
    }
  }

  void
  SCTPDiameterSession::send_packet(const ByteArray& send_packet)
  {
    connection_->lock()->send_packet(send_packet);
  }

  void
  SCTPDiameterSession::get_charging_rules(
    std::unordered_set<std::string>& install_charging_rule_names,
    std::unordered_set<std::string>& remove_charging_rule_names,
    const Diameter::Packet& response)
  {
    for (int i = 0; i < response.numberOfAVPs(); ++i)
    {
      const auto& avp = response.avp(i);
      if (avp.header().avpCode() == 1001) //< Charging-Rule-Install(1001)
      {
        auto avp_data = avp.data().toAVPs();
        for (const auto& sub_avp : avp_data)
        {
          if (sub_avp.header().avpCode() == 1005) //< Charging-Rule-Name(1005)
          {
            std::string charging_rule_name = get_avp_string_value(sub_avp);
            if (!charging_rule_name.empty())
            {
              install_charging_rule_names.emplace(std::move(charging_rule_name));
            }
          }
        }
      }
      else if (avp.header().avpCode() == 1002) //< Charging-Rule-Install(1001)
      {
        auto avp_data = avp.data().toAVPs();
        for (const auto& sub_avp : avp_data)
        {
          if (sub_avp.header().avpCode() == 1005) //< Charging-Rule-Name(1005)
          {
            std::string charging_rule_name = get_avp_string_value(sub_avp);
            if (!charging_rule_name.empty())
            {
              remove_charging_rule_names.emplace(std::move(charging_rule_name));
            }
          }
        }
      }
    }
  }

  SCTPDiameterSession::GxInitResponse
  SCTPDiameterSession::send_gx_init(const Request& request)
  {
    auto [result_code, response, request_key] = send_and_read_response_i_(
      [this, &request] ()
      {
        auto [request_key, request_packet] = generate_gx_init_(request);
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: SEND GX INIT (" <<
          request_key.to_string() << "): " <<
          request.to_string() <<
          std::endl;
        return std::make_pair(request_key, request_packet);
      }
    );

    GxInitResponse init_response;
    init_response.result_code = result_code.has_value() ? *result_code : 0;

    get_charging_rules(
      init_response.install_charging_rule_names,
      init_response.remove_charging_rule_names,
      *response);

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: GX INIT RESPONSE (" <<
      request_key.to_string() << "): " <<
      request.to_string() << " => " <<
      init_response.to_string() <<
      std::endl;
    return init_response;
  }

  SCTPDiameterSession::GxUpdateResponse
  SCTPDiameterSession::send_gx_update(
    const Request& request,
    const GxUpdateRequest& update_request)
  {
    //std::cout << "[DIAMETER] To send Gx update for msisdn = " <<
    //  request.user_session_traits.msisdn << std::endl;

    auto [result_code, response, request_key] = send_and_read_response_i_(
      [this, &request, &update_request] ()
      {
        auto [request_key, request_packet] = generate_gx_update_(request, update_request);
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: SEND GX UPDATE (" <<
          request_key.to_string() << "): " <<
          request.to_string() << ", " <<
          update_request.to_string() << std::endl;
        return std::make_pair(request_key, request_packet);
      }
    );

    GxUpdateResponse update_response;
    update_response.result_code = result_code.has_value() ? *result_code : 0;

    get_charging_rules(
      update_response.install_charging_rule_names,
      update_response.remove_charging_rule_names,
      *response);

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: GX UPDATE RESPONSE (" <<
      request_key.to_string() << "): " <<
      request.to_string() << " => " <<
      update_response.to_string() <<
      std::endl;

    return update_response;
  }

  SCTPDiameterSession::GxTerminateResponse
  SCTPDiameterSession::send_gx_terminate(
    const Request& request,
    const GxTerminateRequest& terminate_request)
  {
    auto [result_code, response, request_key] = send_and_read_response_i_(
      [this, &request, &terminate_request] ()
      {
        auto [request_key, request_packet] = generate_gx_terminate_(request, terminate_request);
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: SEND GX TERMINATE (" <<
          request_key.to_string() << "): " <<
          request.to_string() << ", " <<
          terminate_request.to_string() << std::endl;
        return std::make_pair(request_key, request_packet);
      }
    );

    GxTerminateResponse terminate_response;
    terminate_response.result_code = result_code.has_value() ? *result_code : 0;

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: GX TERMINATE RESPONSE (" <<
      request_key.to_string() << "): " <<
      request.to_string() << " => " <<
      terminate_response.to_string() <<
      std::endl;

    return terminate_response;
  }

  void
  SCTPDiameterSession::parse_gy_response_(GyResponse& gy_response, Diameter::Packet& response)
  {
    std::cout << "to SCTPDiameterSession::parse_gy_response_" << std::endl;

    for (int i = 0; i < response.numberOfAVPs(); ++i)
    {
      const Diameter::AVP& avp = response.avp(i);
      if (avp.header().avpCode() == 456) //< Multiple-Services-Credit-Control(456)
      {
        unsigned long result_code = 0;
        GyResponse::RatingGroupLimit rating_group_limit;
        auto avps = avp.data().toAVPs();

        for (auto local_avp_it = avps.begin(); local_avp_it != avps.end(); ++local_avp_it)
        {
          const Diameter::AVP& local_avp = *local_avp_it;

          if (local_avp.header().avpCode() == 431) //< Granted-Service-Unit(431)
          {
            auto grant_avps = local_avp.data().toAVPs();
            for (auto g_avp_it = grant_avps.begin(); g_avp_it != grant_avps.end(); ++g_avp_it)
            {
              const Diameter::AVP& g_avp = *g_avp_it;
              if (g_avp.header().avpCode() == 421) // < CC-Total-Octets(421)
              {
                rating_group_limit.cc_total_octets = g_avp.data().toUnsigned64();
              }
            }
          }
          else if (local_avp.header().avpCode() == 432) //< Rating-Group(432)
          {
            rating_group_limit.rating_group_id = local_avp.data().toUnsigned32();
          }
          else if (local_avp.header().avpCode() == 448) //< Validity-Time(448)
          {
            rating_group_limit.validity_time = Gears::Time(local_avp.data().toUnsigned32());
          }
          else if (local_avp.header().avpCode() == 268) //< Result-Code(268)
          {
            rating_group_limit.result_code = local_avp.data().toUnsigned32();
          }
          else if (local_avp.header().avpCode() == 869) //< Volume-Quota-Threshold(869)
          {
            rating_group_limit.max_bps = local_avp.data().toUnsigned32();
          }
        }

        gy_response.rating_group_limits.emplace_back(std::move(rating_group_limit));
      }
    }

    std::cout << "from SCTPDiameterSession::parse_gy_response_" << std::endl;
  }

  SCTPDiameterSession::GyResponse
  SCTPDiameterSession::send_gy_init(const GyRequest& request)
  {
    auto [result_code, response, request_key] = send_and_read_response_i_(
      [this, &request] ()
      {
        auto [request_key, request_packet] = generate_gy_init_(request);
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: SEND GY INIT(" <<
          request_key.to_string() << "): " <<
          request.to_string() << std::endl;

        return std::make_pair(request_key, request_packet);;
      }
    );

    GyResponse init_response;
    parse_gy_response_(init_response, *response);
    init_response.result_code = result_code.has_value() ? *result_code : 0;

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: GY INIT RESPONSE (" <<
      request_key.to_string() << "): " <<
      request.to_string() << " => " <<
      init_response.to_string() <<
      std::endl;

    return init_response;
  }

  SCTPDiameterSession::GyResponse
  SCTPDiameterSession::send_gy_update(const GyRequest& request)
  {
    auto [result_code, response, request_key] = send_and_read_response_i_(
      [this, &request] ()
      {
        auto [request_key, request_packet] = generate_gy_update_(request);
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: SEND GY UPDATE(" <<
          request_key.to_string() << "): " <<
          request.to_string() <<
          ", reason = " << request.reason <<
          std::endl;
        return std::make_pair(request_key, request_packet);
      }
    );

    GyResponse init_response;
    parse_gy_response_(init_response, *response);
    init_response.result_code = result_code.has_value() ? *result_code : 0;

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: GY UPDATE RESPONSE (" <<
      request_key.to_string() << "): " <<
      request.to_string() << " => " <<
      init_response.to_string() <<
      std::endl;

    return init_response;
  }

  SCTPDiameterSession::GyResponse
  SCTPDiameterSession::send_gy_terminate(const GyRequest& request)
  {
    auto [result_code, response, request_key] = send_and_read_response_i_(
      [this, &request] ()
      {
        auto [request_key, request_packet] = generate_gy_terminate_(request);
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: SEND GY TERMINATE(" <<
          request_key.to_string() << "): " <<
          request.to_string() << std::endl;
        return std::make_pair(request_key, request_packet);;
      }
    );

    GyResponse init_response;
    parse_gy_response_(init_response, *response);
    init_response.result_code = result_code.has_value() ? *result_code : 0;

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] DIAMETER: GY TERMINATE RESPONSE (" <<
      request_key.to_string() << "): " <<
      request.to_string() << " => " <<
      init_response.to_string() <<
      std::endl;

    return init_response;
  }

  void
  SCTPDiameterSession::responses_reading_()
  {
    while (task_runner_->active())
    {
      try
      {
        std::cout << "[DIAMETER] Reading thread: start reading loop: "
          "connection_ = " << connection_.get() <<
          ", this = " << this <<
          std::endl;

        while (task_runner_->active())
          //< check status of running task runner for correct behavior, when it activated,
          // but SCTPDiameterSession isn't yet.
        {
          try
          {
            connection_->lock()->connect(); // TODO: call hook !!!
          }
          catch(const Gears::Exception& ex)
          {
            //std::cout << "[DIAMETER] Reading thread: error on connect: " << ex.what() <<
            //  std::endl;
            ::sleep(1);
            continue;
          }

          //std::cout << "[DIAMETER] Reading thread: from connect" << std::endl;

          //std::cout << "[DIAMETER] Reading thread: to read input message: "
          //  "connection_ = " << connection_.get() <<
          //  ", this = " << this <<
          //  std::endl;
          std::vector<unsigned char> head_buf = connection_->read_bytes(4);
          uint32_t head = htonl(*(const uint32_t*)head_buf.data());
          int packet_size = head & 0xFFFFFF;
          std::vector<unsigned char> read_buf = connection_->read_bytes(packet_size - 4);
          head_buf.insert(head_buf.end(), read_buf.begin(), read_buf.end());

          std::cout << "[DIAMETER] Reading thread: got input message: "
            "connection_ = " << connection_.get() <<
            ", this = " << this <<
            std::endl;

          std::shared_ptr<Diameter::Packet> response =
            std::make_shared<Diameter::Packet>((ByteArray(&head_buf[0], head_buf.size())));

          if (response->header().commandFlags().isSet(Diameter::Packet::Header::Flags::Bits::Request))
          {
            process_input_request_(*response);
          }
          else
          {
            std::string session_id;
            std::optional<uint32_t> request_i;

            // find CC-Request-Number(415)
            for (int i = 0; i < response->numberOfAVPs(); ++i)
            {
              const auto& avp = response->avp(i);
              if (avp.header().avpCode() == 263)
              {
                session_id = get_avp_string_value(avp);
              }
              else if (avp.header().avpCode() == 415)
              {
                request_i = avp.data().toInteger32();
              }
            }

            std::cout << "[DIAMETER] Reading thread: got RESPONSE #" <<
              (request_i.has_value() ? std::to_string(*request_i) : std::string("null")) <<
              "(" + session_id + ")"
              ", this = " << this <<
              std::endl;

            {
              std::unique_lock<std::mutex> lock(responses_lock_);

              if (request_i.has_value())
              {
                responses_.emplace(RequestKey(session_id, *request_i), response);
              }
              last_response_ = response;
            }

            //std::cout << "[DIAMETER] Reading thread: notify all: last_response_ = " << last_response_.get() <<
            //  ", responses_cond_ = " << &responses_cond_ <<
            //  ", this = " << this << std::endl;
            responses_cond_.notify_all();
          }
        }

        break;
      }
      catch(const Gears::Exception& ex)
      {
        std::cerr << "[DIAMETER] [ERROR] Reading thread: response reading error: " <<
          ex.what() << std::endl;
      }

      // on exception sleep(1) and try reconnect
      connection_->lock()->close();

      // drop all waiting tasks
      {
        std::unique_lock<std::mutex> lock(responses_lock_);

        for (const auto& response_key : wait_responses_)
        {
          responses_.emplace(response_key, nullptr);
        }
      }

      ::sleep(1);
    }

    std::cout << "[DIAMETER] Reading thread: exit reading loop: "
      "connection_ = " << connection_.get() <<
      ", this = " << this <<
      std::endl;
  }

  std::shared_ptr<Diameter::Packet>
  SCTPDiameterSession::wait_response_(const RequestKey& request_key)
  {
    std::shared_ptr<Diameter::Packet> result;

    {
      std::unique_lock<std::mutex> lock(responses_lock_);

      wait_responses_.insert(request_key);

      /*
      std::cout << "[DIAMETER] Waiting thread: wait_response_ step #0: " << (
        request_i.has_value() ? std::to_string(*request_i) : std::string("null")) <<
        ", responses_cond_ = " << &responses_cond_ <<
        ", this = " << this <<
        std::endl;
      */

      responses_cond_.wait(
        lock,
        [this, &request_key]
        {
          /*
          std::cout << "[DIAMETER] Waiting thread: wait_response_ ST: "
            "last_response_ = " << last_response_.get() <<
            ", this = " << this <<
            std::endl;
          */
          return this->responses_.find(request_key) != this->responses_.end();
        }
      );

      wait_responses_.erase(request_key);

      /*
      std::cout << "[DIAMETER] Waiting thread: wait_response_ step #1" <<
        ", this = " << this <<
        std::endl;
      */

      result = std::move(responses_[request_key]);
      responses_.erase(request_key);
    }

    if (!result)
    {
      // connection error
      throw DiameterError("Connection closed");
    }

    return result;
  }

  std::shared_ptr<Diameter::Packet>
  SCTPDiameterSession::wait_response_()
  {
    std::shared_ptr<Diameter::Packet> result;

    {
      std::unique_lock<std::mutex> lock(responses_lock_);

      /*
      std::cout << "[DIAMETER] Waiting thread: wait_response_ step #0: " << (
        request_i.has_value() ? std::to_string(*request_i) : std::string("null")) <<
        ", responses_cond_ = " << &responses_cond_ <<
        ", this = " << this <<
        std::endl;
      */

      responses_cond_.wait(
        lock,
        [this]
        {
          /*
          std::cout << "[DIAMETER] Waiting thread: wait_response_ ST: "
            "last_response_ = " << last_response_.get() <<
            ", this = " << this <<
            std::endl;
          */
          return static_cast<bool>(this->last_response_);
        }
      );

      /*
      std::cout << "[DIAMETER] Waiting thread: wait_response_ step #1" <<
        ", this = " << this <<
        std::endl;
      */

      result.swap(last_response_);
    }

    return result;
  }

  std::pair<SCTPDiameterSession::RequestKey, ByteArray>
  SCTPDiameterSession::generate_gx_init_(const Request& request)
    const
  {
    const RequestKey request_key(get_session_id_(request.session_id_suffix), request.request_id);

    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(
             Diameter::Packet::Header::Flags()
             .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
             .setFlag(Diameter::Packet::Header::Flags::Bits::Proxiable, true)
          )
          .setCommandCode(272)
          .setApplicationId(request.application_id)
          .setHBHIdentifier(Gears::safe_rand())
          .setETEIdentifier(Gears::safe_rand())
      );

    packet
      .addAVP(create_string_avp(263, request_key.session_id, std::nullopt, true)) // Session-Id
      .addAVP(create_uint32_avp(258, request.application_id, std::nullopt, true)) // Auth-Application-Id
      .addAVP(create_string_avp(264, origin_host_, std::nullopt, true)) // Origin-Host
      .addAVP(create_string_avp(296, origin_realm_, std::nullopt, true)) // Origin-Realm
      ;

    if (destination_host_.has_value())
    {
      packet.addAVP(create_string_avp(293, *destination_host_));
    }

    if (destination_realm_.has_value())
    {
      packet.addAVP(create_string_avp(283, *destination_realm_)); // Destination-Realm(283)
    }

    packet
      .addAVP(create_uint32_avp(415, request_key.request_i, std::nullopt, true)) // CC-Request-Number
      .addAVP(create_uint32_avp(278, 3801248757, std::nullopt, true)) // Origin-State-Id
      .addAVP(create_avp( //< QoS-Information
        1016,
        Diameter::AVP::Data()
          .addAVP(create_uint32_avp(1041, 50'000'000, 10415)) //< APN-Aggregate-Max-Bitrate-UL(1041)
          .addAVP(create_uint32_avp(1040, 150'000'000, 10415)), //< APN-Aggregate-Max-Bitrate-DL(1040)
        10415,
        true
        ))
      .addAVP(create_avp( //< Default-EPS-Bearer-QoS
        1049,
        Diameter::AVP::Data()
          .addAVP(create_uint32_avp(1028, 8, 10415)) //< QoS-Class-Identifier
          .addAVP(create_avp( //< Allocation-Retention-Priority
            1034,
            Diameter::AVP::Data()
              .addAVP(create_uint32_avp(1046, 2, 10415)) //< Priority-Level
              .addAVP(create_uint32_avp(1047, 1, 10415)) //< Pre-emption-Capability
              .addAVP(create_uint32_avp(1048, 0, 10415)) //< Pre-emption-Vulnerability
            ,
            10415
            )),
        10415,
        false))
      .addAVP(create_string_avp(30, request.user_session_traits.called_station_id, std::nullopt, true)) // Called-Station-Id
      .addAVP(create_ipv4_avp(
        501,
        request.user_session_traits.access_network_charging_ip_address,
        10415,
        true))
        //< Access-Network-Charging-Address
      .addAVP(create_ipv4_4bytes_avp(8, request.user_session_traits.framed_ip_address, std::nullopt, true)) // Framed-IP-Address
      .addAVP(create_int32_avp(1009, 1, 10415, true)) // Online
      .addAVP(create_int32_avp(1008, 1, 10415, true)) // Offline
      .addAVP(create_avp( //< Access-Network-Charging-Identifier-Gx(1022)
        1022,
        Diameter::AVP::Data()
        .addAVP(create_octets_avp(
          503, //< Access-Network-Charging-Identifier-Value(503)
          uint32_to_buf_(request.user_session_traits.charging_id),
          10415,
          true
        ))
        ,
        10415,
        true
        ))
      .addAVP(create_ipv4_4bytes_avp(6, request.user_session_traits.sgsn_ip_address, 10415, false))
      //< 3GPP-SGSN-Address(6)
      .addAVP(create_ipv4_avp(1050, request.user_session_traits.sgsn_ip_address, 10415, false))
      //< AN-GW-Address(1050)=3GPP-SGSN-Address
      .addAVP(create_uint32_avp(1024, 1, 10415, true)) // Network-Request-Support
      .addAVP(create_string_avp(18, request.user_session_traits.mcc_mnc, 10415, false)) // 3GPP-SGSN-MCC-MNC(18)
      .addAVP(create_uint16_avp(
        23,
        static_cast<uint16_t>(request.user_session_traits.timezone) << 8 | 0, //< Adjustment=0
        10415,
        false
      )) // 3GPP-MS-TimeZone
      // Subscription-Id with IMSI
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
          .addAVP(create_string_avp(444, request.user_session_traits.msisdn)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 1)) // Subscription-Id-Type = END_USER_IMSI
          .addAVP(create_string_avp(444, request.user_session_traits.imsi)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( //< Supported-Features
        628,
        Diameter::AVP::Data()
          .addAVP(create_uint32_avp(266, 10415)) //< Vendor-Id
          .addAVP(create_uint32_avp(629, 1, 10415)) //< Feature-List-Id
          .addAVP(create_uint32_avp(630, 3, 10415)), //< Feature-List 
        10415,
        false))
      .addAVP(create_uint32_avp(1027, 5, 10415, true)) // IP-CAN-Type
      //.addAVP(create_int32_avp()) // Access-Network-Charging-Address
      ;

    DiameterPacketFiller packet_filler(diameter_dictionary_, 272);
    packet_filler.add_avp("RAT-Type", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.rat_type));
    packet_filler.apply(packet);

    if (!request.user_session_traits.user_location_info.empty())
    {
      packet.addAVP(create_octets_avp(
        22,
        ByteArray(
          &request.user_session_traits.user_location_info[0],
          request.user_session_traits.user_location_info.size()),
        10415,
        false
      ));
      //< 3GPP-User-Location-Info
    }
    
    if (!request.user_session_traits.imei.empty())
    {
      packet.addAVP(
        create_avp(
          458, // User-Equipment-Info(458)
          Diameter::AVP::Data()
            .addAVP(create_uint32_avp(459, 0, std::nullopt, false))
            //< User-Equipment-Info-Type(459) = IMEISV
            .addAVP(create_string_avp(
              460,
              request.user_session_traits.imei, std::nullopt, false))
            //< User-Equipment-Info-Type(459)
          ,
          std::nullopt,
          false
        )
      );
    }

    packet.addAVP(create_int32_avp(416, 1, std::nullopt, true)); // CC-Request-Type

    return std::make_pair(
      request_key,
      packet.updateLength().deploy()
    );
  }

  void
  SCTPDiameterSession::fill_gx_stat_update_(
    Diameter::Packet& packet,
    const SCTPDiameterSession::GxUpdateRequest& gx_update_request)
  {
    for (const auto& usage_monitoring : gx_update_request.usage_monitorings)
    {
      packet.addAVP(create_avp(
        1067,
        Diameter::AVP::Data()
          .addAVP(create_avp( // Used-Service-Unit(446)
            446,
            Diameter::AVP::Data()
              .addAVP(create_uint64_avp(421, usage_monitoring.total_octets, std::nullopt, true)), // CC-Total-Octets(421)
            std::nullopt,
            true))
          .addAVP(create_uint32_avp(1066, usage_monitoring.monitoring_key, 10415, false)) // Monitoring-Key(1066)
          .addAVP(create_uint32_avp(1068, usage_monitoring.usage_monitoring_level, 10415, false)), // Usage-Monitoring-Level(1068)
        10415,
        false
      ));
    }

    for (const auto& not_found_charging_rule_name : gx_update_request.not_found_charging_rule_names)
    {
      packet.addAVP(create_avp(
        1018, // Charging-Rule-Report
        Diameter::AVP::Data()
          .addAVP(create_string_avp(1005, not_found_charging_rule_name, 10415, true)) // Charging-Rule-Name
          .addAVP(create_uint32_avp(1031, 1, 10415, true)) // Rule-Failure-Code: UNKNOWN_RULE_NAME=1
          .addAVP(create_uint32_avp(1019, 1, 10415, true)) // PCC-Rule-Status=INACTIVE
        ,
        10415,
        true
      ));
    }
  }

  std::pair<SCTPDiameterSession::RequestKey, ByteArray>
  SCTPDiameterSession::generate_gx_update_(
    const Request& request,
    const GxUpdateRequest& update_request)
    const
  {
    auto [request_key, packet] = generate_base_gx_packet_(request);
    fill_gx_stat_update_(packet, update_request);
    packet.addAVP(create_int32_avp(416, 2)); // CC-Request-Type

    return std::make_pair(
      request_key,
      packet.updateLength().deploy()
    );
  }

  std::pair<SCTPDiameterSession::RequestKey, ByteArray>
  SCTPDiameterSession::generate_gx_terminate_(
    const Request& request,
    const GxTerminateRequest& terminate_request)
    const
  {
    auto [request_key, packet] = generate_base_gx_packet_(request);

    fill_gx_stat_update_(packet, terminate_request);

    packet
      //.addAVP(create_uint32_avp(1006, terminate_request.event_trigger, 10415, true)) // Event-Trigger(1006)
      .addAVP(create_uint32_avp(295, terminate_request.termination_cause, std::nullopt, true)) // Termination-Cause(295)
      .addAVP(create_int32_avp(416, 3)) // CC-Request-Type
      ;

    return std::make_pair(
      request_key,
      packet.updateLength().deploy()
    );
  }

  ByteArray
  SCTPDiameterSession::generate_watchdog_packet_(
    uint32_t hbh_identifier,
    uint32_t ete_identifier) const
  {
    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(Diameter::Packet::Header::Flags())
          .setCommandCode(280)
          .setApplicationId(0)
          .setHBHIdentifier(hbh_identifier)
          .setETEIdentifier(ete_identifier)
      );

    packet
      .addAVP(create_string_avp(264, origin_host_, std::nullopt, true)) // Origin-Host(264)
      .addAVP(create_string_avp(296, origin_realm_, std::nullopt, true)) // Origin-Host(264)
      .addAVP(create_uint32_avp(278, origin_state_id_, std::nullopt, true)) // Origin-Host(264)
      .addAVP(create_uint32_avp(268, 2001, std::nullopt, true)) // Origin-Host(268)
      ;

    return packet
      .updateLength()
      .deploy();
  }

  std::pair<SCTPDiameterSession::RequestKey, ByteArray>
  SCTPDiameterSession::generate_gy_init_(const GyRequest& request) const
  {
    auto [request_key, packet] = generate_base_gy_packet_(request, std::nullopt);

    packet.addAVP(create_int32_avp(416, 1, std::nullopt, true)); // CC-Request-Type

    return std::make_pair(
      request_key,
      packet.updateLength().deploy()
    );
  }

  std::pair<SCTPDiameterSession::RequestKey, ByteArray>
  SCTPDiameterSession::generate_gy_update_(const GyRequest& request) const
  {
    auto [request_key, packet] = generate_base_gy_packet_(request, std::nullopt);

    packet.addAVP(create_int32_avp(416, 2, std::nullopt, true)); // CC-Request-Type

    return std::make_pair(
      request_key,
      packet.updateLength().deploy()
    );
  }

  std::pair<SCTPDiameterSession::RequestKey, ByteArray>
  SCTPDiameterSession::generate_gy_terminate_(const GyRequest& request) const
  {
    auto [request_key, packet] = generate_base_gy_packet_(request, 2);

    packet.addAVP(create_int32_avp(295, 1, std::nullopt, true)); // Termination-Cause(295)=DIAMETER_LOGOUT
    packet.addAVP(create_int32_avp(416, 3, std::nullopt, true)); // CC-Request-Type

    return std::make_pair(
      request_key,
      packet.updateLength().deploy()
    );
  }

  std::pair<SCTPDiameterSession::RequestKey, Diameter::Packet>
  SCTPDiameterSession::generate_base_gy_packet_(
    const GyRequest& request,
    const std::optional<unsigned int>& reporting_reason) const
  {
    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(
             Diameter::Packet::Header::Flags()
             .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
             .setFlag(Diameter::Packet::Header::Flags::Bits::Proxiable, true)
          )
          .setCommandCode(272)
          .setApplicationId(request.application_id)
          .setHBHIdentifier(Gears::safe_rand())
          .setETEIdentifier(Gears::safe_rand())
      );

    const auto session_id = get_session_id_(request.session_id_suffix);
    const unsigned int request_i = request.request_id;

    packet
      .addAVP(create_string_avp(263, session_id, std::nullopt, true)) // Session-Id
      .addAVP(create_uint32_avp(258, request.application_id, std::nullopt, true)) // Auth-Application-Id
      .addAVP(create_string_avp(264, origin_host_, std::nullopt, true)) // Origin-Host
      .addAVP(create_string_avp(296, origin_realm_, std::nullopt, true)) // Origin-Realm
      ;

    if (destination_host_.has_value())
    {
      packet.addAVP(create_string_avp(293, *destination_host_));
    }

    if (destination_realm_.has_value())
    {
      packet.addAVP(create_string_avp(283, *destination_realm_)); // Destination-Realm(283)
    }

    packet
      .addAVP(create_uint32_avp(415, request_i, std::nullopt, true)) // CC-Request-Number
      .addAVP(create_uint32_avp(278, origin_state_id_, std::nullopt, true)) // Origin-State-Id
      .addAVP(create_uint32_avp(55, Gears::Time::get_time_of_day().tv_sec, std::nullopt, true)) // Event-Timestamp(55)
      // Subscription-Id with IMSI
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
          .addAVP(create_string_avp(444, request.user_session_traits.msisdn)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 1)) // Subscription-Id-Type = END_USER_IMSI
          .addAVP(create_string_avp(444, request.user_session_traits.imsi)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_uint32_avp(455, 1, std::nullopt, true)) // Multiple-Services-Indicator(455)
      ;

    for (const auto& rating_group : request.usage_rating_groups)
    {
      auto avp_data = Diameter::AVP::Data()
        .addAVP(create_uint32_avp(432, rating_group.rating_group_id, std::nullopt, true)) // Rating-Group(432)
        .addAVP(create_avp(
          437, // Requested-Service-Unit(437)
          Diameter::AVP::Data()
          //  .addAVP(create_uint64_avp(421, 1024*1024, std::nullopt, true)) // NO IN PCAP ! CC-Total-Octets(421)
          ,
          std::nullopt,
          true
        )
      );

      if (rating_group.total_octets > 0)
      {
        Diameter::AVP::Data used_avp_data;
        used_avp_data.addAVP(create_uint64_avp(421, rating_group.total_octets, std::nullopt, true));
        if (reporting_reason.has_value())
        {
          used_avp_data.addAVP(create_uint32_avp(872, *reporting_reason, 10415, true)); // 3GPP-Reporting-Reason(872)=THRESHOLD
        }

        avp_data.addAVP(create_avp(
          446, // Used-Service-Unit(446)
          used_avp_data,
          std::nullopt,
          true
        ));
      }

      packet.addAVP(
        create_avp(
          456, // Multiple-Services-Credit-Control(456)
          avp_data,
          std::nullopt,
          true
        )
      );
    }

    if (!request.user_session_traits.imei.empty())
    {
      packet.addAVP(
        create_avp(
          458, // User-Equipment-Info(458)
          Diameter::AVP::Data()
            .addAVP(create_uint32_avp(459, 0, std::nullopt, false))
            //< User-Equipment-Info-Type(459) = IMEISV
            .addAVP(create_string_avp(460, request.user_session_traits.imei, std::nullopt, false))
            //< User-Equipment-Info-Type(459)
          ,
          std::nullopt,
          false
        )
      );
    }

    /*
    if (!USE_FILLER_)
    {
      auto ps_information_avp_data = Diameter::AVP::Data()
        .addAVP(create_uint32_avp(2, request.user_session_traits.charging_id, 10415, false)) // 3GPP-Charging-Id(2)
        .addAVP(create_uint32_avp(3, 0, 10415, false)) // 3GPP-PDP-Type(3)=IPv4
        .addAVP(create_ipv4_avp(1227, request.user_session_traits.framed_ip_address, 10415, true))
        //< PDP-Address(1227)=framed_ip_address
        .addAVP(create_ipv4_avp(1228, request.user_session_traits.sgsn_ip_address, 10415, true))
        //< SGSN-Address(1228)
        .addAVP(create_ipv4_avp(847, request.user_session_traits.access_network_charging_ip_address, 10415, true))
        //< GGSN-Address(847)
        .addAVP(create_ipv4_avp(846, request.user_session_traits.sgsn_ip_address, 10415, true))
        //< CG-Address(846) // ???
        .addAVP(create_string_avp(8, request.user_session_traits.mcc_mnc, 10415, false)) // 3GPP-IMSI-MCC-MNC(8)
        .addAVP(create_string_avp(9, request.user_session_traits.mcc_mnc, 10415, false)) // 3GPP-GGSN-MCC-MNC(9)
        .addAVP(create_string_avp(30, request.user_session_traits.called_station_id, std::nullopt, true))
        //< Called-Station-Id(30)
        .addAVP(create_string_avp(18, request.user_session_traits.mcc_mnc, 10415, false))
        //< 3GPP-SGSN-MCC-MNC(18)
        .addAVP(create_uint16_avp(
          23,
          static_cast<uint16_t>(request.user_session_traits.timezone) << 8 | 0, //< Adjustment=0
          10415,
          false
        )) // 3GPP-MS-TimeZone
        .addAVP(create_uint32_avp(21, request.user_session_traits.rat_type, 10415, false)) // 3GPP-RAT-Type(21)
        .addAVP(create_uint32_avp(1247, 0, 10415, false)) // PDP-Context-Type(1247)=PRIMARY
        .addAVP(create_uint32_avp(2050, request.user_session_traits.charging_id, 10415, true))
        //< PDN-Connection-Charging-ID(2050)
        .addAVP(create_uint32_avp(2047, 2, 10415, true)) //< Serving-Node-Type(2047)=GTPSGW
        ;

      // .addAVP(create_string_avp(1004, "up_bypass", 10415, true)) // Charging-Rule-Base-Name(1004)=up_bypass

      if (!request.user_session_traits.charging_characteristics.empty())
      {
        ps_information_avp_data.addAVP(create_string_avp(
          13, // 3GPP-Charging-Characteristics(13)
          request.user_session_traits.charging_characteristics,
          10415,
          false));
      }

      if (!request.user_session_traits.selection_mode.empty())
      {
        ps_information_avp_data.addAVP(create_string_avp(
          12, // 3GPP-Selection-Mode(12)
          request.user_session_traits.selection_mode,
          10415,
          false));
      }

      if (!request.user_session_traits.nsapi.empty())
      {
        ps_information_avp_data.addAVP(create_string_avp(
          10, // 3GPP-NSAPI(10)
          request.user_session_traits.nsapi,
          10415,
          false));
      }

      if (!request.user_session_traits.user_location_info.empty())
      {
        ps_information_avp_data.addAVP(create_octets_avp(
          22, // 3GPP-User-Location-Info(22)
          ByteArray(
            &request.user_session_traits.user_location_info[0],
            request.user_session_traits.user_location_info.size()),
          10415,
          false));
      }

      if (!request.user_session_traits.gprs_negotiated_qos_profile.empty())
      {
        ps_information_avp_data.addAVP(create_string_avp(
          5, //< 3GPP-GPRS-Negotiated-QoS-Profile(5)
          request.user_session_traits.gprs_negotiated_qos_profile,
          10415,
          false));
      }

      packet.addAVP(
        create_avp(
          873, // Service-Information(873)
          Diameter::AVP::Data().addAVP(
            create_avp(
              874, // PS-Information(874)
              ps_information_avp_data,
              10415,
              true
            )
          ),
          10415,
          true
        )
      );
    }
    else
    {
    }
    */

    DiameterPacketFiller packet_filler(diameter_dictionary_, 272);
    packet_filler.add_avp("Service-Information.PS-Information.PDP-Address", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.framed_ip_address));
    packet_filler.add_avp("Service-Information.PS-Information.SGSN-Address", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.sgsn_ip_address));
    packet_filler.add_avp("Service-Information.PS-Information.GGSN-Address", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.access_network_charging_ip_address));
    packet_filler.add_avp("Service-Information.PS-Information.CG-Address", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.sgsn_ip_address));

    packet_filler.add_avp("Service-Information.PS-Information.3GPP-Charging-Id", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.charging_id));
    packet_filler.add_avp("Service-Information.PS-Information.3GPP-PDP-Type", dpi::Value(std::in_place_type<uint64_t>, 0));

    packet_filler.add_avp("Service-Information.PS-Information.3GPP-RAT-Type",
      dpi::Value(ByteArrayValue({static_cast<uint8_t>(request.user_session_traits.rat_type)}))); // adapter
    packet_filler.add_avp("Service-Information.PS-Information.PDN-Connection-Charging-ID", dpi::Value(std::in_place_type<uint64_t>, request.user_session_traits.charging_id));
    packet_filler.add_avp("Service-Information.PS-Information.Serving-Node-Type", dpi::Value(std::in_place_type<uint64_t>, 2));
    packet_filler.add_avp("Service-Information.PS-Information.PDP-Context-Type", dpi::Value(std::in_place_type<uint64_t>, 0));
    packet_filler.add_avp("Service-Information.PS-Information.3GPP-MS-TimeZone",
      dpi::Value(ByteArrayValue({static_cast<uint8_t>(request.user_session_traits.timezone), 0}))); // adapter
    packet_filler.add_avp("Service-Information.PS-Information.Called-Station-Id", dpi::Value(request.user_session_traits.called_station_id));
    packet_filler.add_avp("Service-Information.PS-Information.3GPP-GGSN-MCC-MNC", dpi::Value(request.user_session_traits.mcc_mnc));
    packet_filler.add_avp("Service-Information.PS-Information.3GPP-SGSN-MCC-MNC", dpi::Value(request.user_session_traits.mcc_mnc));
    packet_filler.add_avp("Service-Information.PS-Information.3GPP-IMSI-MCC-MNC", dpi::Value(request.user_session_traits.mcc_mnc));
    packet_filler.add_non_empty_avp("Service-Information.PS-Information.3GPP-Charging-Characteristics",
      dpi::Value(request.user_session_traits.charging_characteristics));
    packet_filler.add_non_empty_avp("Service-Information.PS-Information.3GPP-Selection-Mode",
      dpi::Value(request.user_session_traits.selection_mode));
    packet_filler.add_non_empty_avp("Service-Information.PS-Information.3GPP-NSAPI", dpi::Value(request.user_session_traits.nsapi));
    packet_filler.add_non_empty_avp("Service-Information.PS-Information.3GPP-User-Location-Info",
      dpi::Value(request.user_session_traits.user_location_info));
    std::cout << "DEBUG GY : request.user_session_traits.gprs_negotiated_qos_profile.size() = " <<
      request.user_session_traits.gprs_negotiated_qos_profile.size() << std::endl;
    packet_filler.add_non_empty_avp("Service-Information.PS-Information.3GPP-GPRS-Negotiated-QoS-Profile",
      dpi::Value(request.user_session_traits.gprs_negotiated_qos_profile));
    packet_filler.apply(packet);

    return std::make_pair(RequestKey(session_id, request_i), packet);
  }

  std::pair<SCTPDiameterSession::RequestKey, Diameter::Packet>
  SCTPDiameterSession::generate_base_gx_packet_(const Request& request)
    const
  {
    const RequestKey request_key(get_session_id_(request.session_id_suffix), request.request_id);

    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(
             Diameter::Packet::Header::Flags()
             .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
             .setFlag(Diameter::Packet::Header::Flags::Bits::Proxiable, true)
          )
          .setCommandCode(272)
          .setApplicationId(request.application_id)
          .setHBHIdentifier(Gears::safe_rand())
          .setETEIdentifier(Gears::safe_rand())
      );

    packet
      .addAVP(create_string_avp(263, request_key.session_id, std::nullopt, true)) // Session-Id
      .addAVP(create_uint32_avp(258, request.application_id, std::nullopt, true)) // Auth-Application-Id
      .addAVP(create_string_avp(264, origin_host_, std::nullopt, true)) // Origin-Host
      .addAVP(create_string_avp(296, origin_realm_, std::nullopt, true)) // Origin-Realm
      ;

    if (destination_host_.has_value())
    {
      packet.addAVP(create_string_avp(293, *destination_host_));
    }

    if (destination_realm_.has_value())
    {
      packet.addAVP(create_string_avp(283, *destination_realm_));
    }

    packet
      .addAVP(create_uint32_avp(415, request_key.request_i, std::nullopt, true)) // CC-Request-Number
      .addAVP(create_uint32_avp(278, origin_state_id_, std::nullopt, true)) // Origin-State-Id
      .addAVP(create_string_avp(30, request.user_session_traits.called_station_id, std::nullopt, true))
      //< Called-Station-Id
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
          .addAVP(create_string_avp(444, request.user_session_traits.msisdn)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 1)) // Subscription-Id-Type = END_USER_IMSI
          .addAVP(create_string_avp(444, request.user_session_traits.imsi)), // Subscription-Id-Data
        std::nullopt,
        true
      ));

    return std::make_pair(request_key, packet);
  }

  void
  SCTPDiameterSession::make_exchange(
    BaseConnection& connection,
    const std::string& origin_host,
    const std::string& origin_realm,
    const std::optional<std::string>& destination_host,
    const std::optional<std::string>& destination_realm,
    const std::string& product_name,
    const std::vector<uint32_t>& applications,
    const std::vector<std::string>& source_addresses)
  {
    auto exchange_packet = generate_exchange_packet_(
      origin_host,
      origin_realm,
      destination_host,
      destination_realm,
      product_name,
      applications,
      source_addresses
    );

    auto connection_lock = connection.lock();
    connection_lock->send_packet(exchange_packet);

    std::vector<unsigned char> head_buf = connection_lock->read_bytes(4);
    uint32_t head = htonl(*(const uint32_t*)head_buf.data());
    int packet_size = head & 0xFFFFFF;

    std::vector<unsigned char> read_buf = connection_lock->read_bytes(packet_size - 4);
    head_buf.insert(head_buf.end(), read_buf.begin(), read_buf.end());

    Diameter::Packet response(ByteArray(&head_buf[0], head_buf.size()));

    std::optional<uint32_t> result_code;
    for (int i = 0; i < response.numberOfAVPs(); ++i)
    {
      const Diameter::AVP& avp = response.avp(i);
      if (avp.header().avpCode() == 268) //< Result-Code
      {
        result_code = avp.data().toUnsigned32();
      }
    }

    if (!result_code.has_value())
    {
      throw DiameterError("Prime exchange failed, no Result-Code in response");
    }
    else if(*result_code != 2001)
    {
      std::ostringstream ostr;
      ostr << "Prime exchange failed, Result-Code: " << *result_code;
      throw DiameterError(ostr.str());
    }
  }

  std::string
  SCTPDiameterSession::get_session_id_(const std::string& session_id_suffix) const
  {
    return origin_host_ + session_id_suffix;
  }

  ByteArray
  SCTPDiameterSession::generate_exchange_packet_(
    const std::string& origin_host,
    const std::string& origin_realm,
    const std::optional<std::string>& destination_host,
    const std::optional<std::string>& destination_realm,
    const std::string& product_name,
    const std::vector<uint32_t>& applications,
    const std::vector<std::string>& source_addresses)
  {
    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          // Setting that it's request 
          .setCommandFlags(
             Diameter::Packet::Header::Flags()
             .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
          )
          .setCommandCode(257)
          .setApplicationId(0)
          .setHBHIdentifier(Gears::safe_rand())
          .setETEIdentifier(Gears::safe_rand())
       );

    if (destination_host.has_value())
    {
      packet.addAVP(create_string_avp(293, *destination_host));
    }

    if (destination_realm.has_value())
    {
      packet.addAVP(create_string_avp(283, *destination_realm));
    }

    if (!source_addresses.empty())
    {
      for (const auto& source_addr_str : source_addresses)
      {
        packet.addAVP(create_ipv4_avp(257, string_to_ipv4_address(source_addr_str))); // Host-IP-Address(257)
      }
    }

    packet
      .addAVP(create_string_avp(264, origin_host)) // Origin-Host
      .addAVP(create_string_avp(296, origin_realm)) // Origin-Realm
      .addAVP(create_uint32_avp(266, 2011)) // Vendor-Id
      .addAVP(create_string_avp(269, product_name)) // "Diameter Credit Control Application")) // Product-Name
      .addAVP(create_uint32_avp(299, 0)) // Inband-Security-Id
      ;

    for (const auto& app : applications)
    {
      packet.addAVP(create_uint32_avp(258, app)); // Auth-Application-Id
    }

    return packet.updateLength().deploy();
  }

  ByteArray SCTPDiameterSession::uint32_to_buf_(uint32_t val)
  {
    const uint8_t BUF[] = {
      static_cast<uint8_t>((val >> 24) & 0xFF),
      static_cast<uint8_t>((val >> 16) & 0xFF),
      static_cast<uint8_t>((val >> 8) & 0xFF),
      static_cast<uint8_t>(val & 0xFF)
    };

    return ByteArray(BUF, sizeof(BUF));
  }
}
