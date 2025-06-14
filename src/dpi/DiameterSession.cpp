#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/sctp.h>

#include <iostream>
#include <optional>

#include <gears/StringManip.hpp>
#include <gears/Rand.hpp>
#include <gears/Time.hpp>

#include "AVPUtils.hpp"

#include "DiameterSession.hpp"


namespace dpi
{
  DiameterSession::DiameterSession(
    dpi::LoggerPtr logger,
    std::vector<Endpoint> local_endpoints,
    std::vector<Endpoint> connect_endpoints,
    std::string origin_host,
    std::string origin_realm,
    std::optional<std::string> destination_host,
    std::optional<std::string> destination_realm,
    unsigned long auth_application_id,
    std::string product_name,
    bool keep_open_connection,
    const std::vector<std::string>& source_addresses // source addresses for diameter packet
    )
    : logger_(std::move(logger)),
      local_endpoints_(std::move(local_endpoints)),
      connect_endpoints_(std::move(connect_endpoints)),
      origin_host_(std::move(origin_host)),
      origin_realm_(std::move(origin_realm)),
      destination_host_(std::move(destination_host)),
      destination_realm_(std::move(destination_realm)),
      application_id_(auth_application_id),
      request_i_(0),
      socket_fd_(0),
      keep_open_connection_(keep_open_connection),
      product_name_(product_name),
      origin_state_id_(3801248757)
  {
    for (const auto& addr_str : source_addresses)
    {
      source_addresses_.emplace_back(string_to_ipv4_address(addr_str));
    }

    session_id_ = origin_host_ + ";" + std::to_string(Gears::safe_rand()) + ";0;" +
      std::to_string(Gears::safe_rand());

    if (keep_open_connection_)
    {
      try
      {
        socket_init_();
      }
      catch(const Gears::Exception&)
      {}
    }
  }

  DiameterSession::~DiameterSession()
  {
    socket_close_();
  }

  void
  DiameterSession::set_logger(dpi::LoggerPtr logger)
  {
    logger_.swap(logger);
  }

  std::pair<std::optional<uint32_t>, Diameter::Packet>
  DiameterSession::send_and_read_response_(const ByteArray& send_packet)
  {
    for (int retry_i = 0; retry_i < RETRY_COUNT_; ++retry_i)
    {
      try
      {
        Diameter::Packet response;

        {
          std::unique_lock<std::mutex> guard(send_lock_);
          send_packet_(send_packet);

          while (true)
          {
            response = read_packet_();

            if (response.header().commandFlags().isSet(Diameter::Packet::Header::Flags::Bits::Request))
            {
              // response to watchdog
              if (response.header().commandCode() == 280) // Command: Device-Watchdog
              {
                std::cout << "[DEBUG] Send response for Watchdog request" << std::endl;
                // RESPONSE WATCHDOG
                auto watchdog_packet = generate_watchdog_packet_();
                send_packet_(watchdog_packet);
              }
              else
              {
                std::cout << "[ERROR] Request(Command-Code = " << response.header().commandCode() <<
                  ") that can't be processed" << std::endl;
              }
            }
            else
            {
              break;
            }
          }
        }

        std::optional<uint32_t> result_code;
        for (int i = 0; i < response.numberOfAVPs(); ++i)
        {
          const Diameter::AVP& avp = response.avp(i);
          if (avp.header().avpCode() == 268) //< Result-Code
          {
            result_code = avp.data().toUnsigned32();
          }
        }

        return std::make_pair(result_code, response);
      }
      catch(const std::exception& ex)
      {
        if (logger_)
        {
          std::ostringstream ostr;
          ostr << "[DEBUG] Diameter exception: " << ex.what() << " (socket = " << socket_fd_ << ")";
          logger_->log(ostr.str());
        }

        if (retry_i == RETRY_COUNT_ - 1)
        {
          throw;
        }
      }
    }

    return std::make_pair(0, Diameter::Packet());
  }

  DiameterSession::GxInitResponse
  DiameterSession::send_gx_init(const Request& request)
  {
    std::cout << "[DEBUG] To send Gx init" << std::endl;
    const ByteArray send_packet = generate_gx_init_(request);
    auto [result_code, response] = send_and_read_response_(send_packet);

    GxInitResponse init_response;
    init_response.result_code = result_code.has_value() ? *result_code : 0;
    return init_response;
  }

  DiameterSession::GxUpdateResponse
  DiameterSession::send_gx_update(
    const Request& request,
    const GxUpdateRequest& update_request)
  {
    std::cout << "[DEBUG] To send Gx update for msisdn = " << request.msisdn << std::endl;

    const ByteArray send_packet = generate_gx_update_(request, update_request);
    auto [result_code, response] = send_and_read_response_(send_packet);

    GxUpdateResponse update_response;
    update_response.result_code = result_code.has_value() ? *result_code : 0;
    return update_response;
  }

  DiameterSession::GxTerminateResponse
  DiameterSession::send_gx_terminate(
    const Request& request,
    const GxTerminateRequest& terminate_request)
  {
    const ByteArray send_packet = generate_gx_terminate_(request, terminate_request);
    auto [result_code, response] = send_and_read_response_(send_packet);

    GxTerminateResponse terminate_response;
    terminate_response.result_code = result_code.has_value() ? *result_code : 0;
    return terminate_response;
  }

  DiameterSession::GyResponse
  DiameterSession::send_gy_init(const GyRequest& request)
  {
    const ByteArray send_packet = generate_base_gy_packet_(request);
    auto [result_code, response] = send_and_read_response_(send_packet);

    GyResponse init_response;
    init_response.result_code = result_code.has_value() ? *result_code : 0;
    return init_response;
  }

  Diameter::Packet
  DiameterSession::read_packet_()
  {
    std::vector<unsigned char> head_buf = read_bytes_(4);
    uint32_t head = htonl(*(const uint32_t*)head_buf.data());
    int packet_size = head & 0xFFFFFF;
    //std::cout << "readed = " << read_res << ", packet_size = " << packet_size << std::endl;

    std::vector<unsigned char> read_buf = read_bytes_(packet_size - 4);
    head_buf.insert(head_buf.end(), read_buf.begin(), read_buf.end());

    try
    {
      std::cout << "[DEBUG] To parse diameter packet (bytes = " << head_buf.size() <<
        ", request-number = " << request_i_ <<
        ")" << std::endl;
      return Diameter::Packet(ByteArray(&head_buf[0], head_buf.size()));
    }
    catch (const std::invalid_argument& ex)
    {
      throw DiameterError(std::string("Can't parse response: ") + ex.what());
    }
  }

  void
  DiameterSession::send_packet_(const ByteArray& send_packet)
  {
    if (socket_fd_ <= 0)
    {
      socket_init_();
    }

    int res = ::write(socket_fd_, send_packet.data(), send_packet.size());
    if (res < send_packet.size())
    {
      socket_close_();
      throw NetworkError("Write failed");
    }

    std::cout << "[DEBUG] From send diameter packet (bytes = " << send_packet.size() <<
      ", request-number = " << request_i_ <<
      ")" << std::endl;
  }

  void
  DiameterSession::socket_close_()
  {
    if (socket_fd_ > 0)
    {
      ::close(socket_fd_);
      socket_fd_ = 0;
    }
  }

  std::vector<unsigned char>
  DiameterSession::read_bytes_(unsigned long size)
  {
    std::vector<unsigned char> buf(size);
    int read_pos = 0;
    while(read_pos < size)
    {
      int read_res = ::read(socket_fd_, &buf[read_pos], size - read_pos);
      std::cout << "[DEBUG] Diameter read finished (bytes = " << read_res << ")" << std::endl;

      if (read_res < 0)
      {
        char error_buf[128];
        int e = errno;
        char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
        std::ostringstream ostr;
        ostr << "Diameter head read error, errno = " << e << ", message = " << error_msg;
        throw NetworkError(ostr.str());
      }
      else if (read_res == 0)
      {
        if (errno != EINPROGRESS || errno != EAGAIN)
        {
          socket_close_();
          throw ConnectionClosedOnRead("Connection closed on read");
        }
      }

      read_pos += read_res;
    }

    return buf;
  }

  void
  DiameterSession::fill_addr_(struct sockaddr_in& res, const Endpoint& endpoint)
  {
    struct hostent* server = ::gethostbyname(endpoint.host.c_str());
    if(server == NULL)
    {
      std::ostringstream ostr;
      ostr << "Can't resolve host: " << endpoint.host;
    }

    bzero((char*)&res, sizeof(res));
    res.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char*)&res.sin_addr.s_addr, server->h_length);
    res.sin_port = ::htons(endpoint.port);
  }

  void
  DiameterSession::socket_init_()
  {
    int socket_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if(socket_fd < 0)
    {
      throw NetworkError("Cannot open socket");
    }

    int val = 1;
    ::setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));

    try
    {
      // Bind local addresses
      if (!local_endpoints_.empty())
      {
        unsigned int result_local_port = local_endpoints_.begin()->port;
        unsigned int local_addr_i = 0;
        for (auto addr_it = local_endpoints_.begin(); addr_it != local_endpoints_.end();
          ++addr_it, ++local_addr_i)
        {
          sockaddr_in local_addr;
          fill_addr_(local_addr, *addr_it);
          local_addr.sin_port = ::htons(result_local_port);

          int res;

          if (local_addr_i == 0)
          {
            res = ::bind(socket_fd, (sockaddr*)&local_addr, sizeof(sockaddr_in));
          }
          else
          {
            res = ::sctp_bindx(socket_fd, (sockaddr*)&local_addr, 1, SCTP_BINDX_ADD_ADDR);
          }

          if (res < 0)
          {
            char error_buf[128];
            int e = errno;
            char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
            std::ostringstream ostr;
            ostr << "Cannot bind to " << addr_it->host << ":" << addr_it->port <<
              ": errno = " << e << ", message = " << error_msg;
            throw NetworkError(ostr.str());
          }

          if (local_addr_i == 0 && addr_it->port == 0)
          {
            struct sockaddr_in local_addr;
            socklen_t len = sizeof(sockaddr_in);
            res = ::getsockname(socket_fd, (sockaddr*)&local_addr, &len);

            if (res < 0)
            {
              char error_buf[128];
              int e = errno;
              char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
              std::ostringstream ostr;
              ostr << "Cannot get sock addr: errno = " << e << ", message = " << error_msg;
              throw NetworkError(ostr.str());
            }

            result_local_port = ::ntohs(local_addr.sin_port);
          }
        }
      }

      // Connect
      std::vector<struct sockaddr_in> connect_addrs(connect_endpoints_.size());
      unsigned int conn_i = 0;
      for (auto conn_it = connect_endpoints_.begin(); conn_it != connect_endpoints_.end(); ++conn_it, ++conn_i)
      {
        fill_addr_(connect_addrs[conn_i], *conn_it);
      }

      int res = ::sctp_connectx(
        socket_fd,
        (sockaddr*)&connect_addrs[0],
        connect_addrs.size(),
        NULL);

      if(res < 0)
      {
        if (errno == EINPROGRESS)
        {
          fd_set fdset;
          do
          {
            struct timeval tv;
            tv.tv_sec = 3;
            tv.tv_usec = 0;
            FD_ZERO(&fdset);
            FD_SET(socket_fd, &fdset);
            int res = ::select(socket_fd + 1, NULL, &fdset, NULL, &tv);
            if (res < 0 && errno != EINTR)
            {
              throw NetworkError("Connecting error");
            }
            else if (res > 0)
            {
              break;
            }
            else
            {
              throw NetworkError("Timeout on connection");
            }
          }
          while (true);
        }
        else
        {
          char error_buf[128];
          int e = errno;
          char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
          std::ostringstream ostr;
          ostr << "Cannot connect: errno = " << e << ", message = " << error_msg;
          throw NetworkError(ostr.str());
        }
      }
    }
    catch(...)
    {
      if (socket_fd > 0)
      {
        ::close(socket_fd);
      }

      throw;
    }

    socket_fd_ = socket_fd;

    // Init diameter session
    auto exchange_packet = generate_exchange_packet_();
    send_packet_(exchange_packet);
    Diameter::Packet response = read_packet_();
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
      socket_close_();
      throw DiameterError("Prime exchange failed, no Result-Code in response");
    }
    else if(*result_code != 2001)
    {
      socket_close_();
      std::ostringstream ostr;
      ostr << "Prime exchange failed, Result-Code: " << *result_code;
      throw DiameterError(ostr.str());
    }
  }

  ByteArray
  DiameterSession::generate_gx_init_(const Request& request)
    const
  {
    const uint8_t USER_LOCATION[] = {
      0x82, // Geographic Location Type: TAI and ECGI (130)
      0x52, 0xf0, 0x02, 0x6c, 0xf6,
      0x52, 0xf0, 0x02, 0x07, 0xad, 0xde, 0x51
    };

    const uint8_t USER_EQUIPMENT_INFO[] = {
      0x00, 0x00, 0x01, 0xcb, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0xcc, 0x00, 0x00, 0x00, 0x18, 0x33, 0x35, 0x37, 0x32,
      0x34, 0x38, 0x37, 0x37, 0x39, 0x30, 0x35, 0x39, 0x32, 0x32, 0x30, 0x31
    };

    const uint8_t QOS_INFO[] = {
      0x00, 0x00, 0x04, 0x11, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf,
      0x02, 0xfa, 0xf0, 0x80, 0x00, 0x00, 0x04, 0x10, 0x80, 0x00, 0x00, 0x10,
      0x00, 0x00, 0x28, 0xaf, 0x08, 0xf0, 0xd1, 0x80
    };

    const uint8_t TZ_INFO[] = {
      0x21, 0x00
    };

    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(
             Diameter::Packet::Header::Flags()
             .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
             .setFlag(Diameter::Packet::Header::Flags::Bits::Proxiable, true)
          )
          .setCommandCode(272)
          .setApplicationId(application_id_)
          .setHBHIdentifier(0x7ddf9367)
          .setETEIdentifier(0xc15ecb12)
      );

    packet
      .addAVP(create_string_avp(263, session_id_, std::nullopt, true)) // Session-Id
      .addAVP(create_uint32_avp(258, application_id_, std::nullopt, true)) // Auth-Application-Id
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
      .addAVP(create_uint32_avp(415, ++request_i_, std::nullopt, true)) // CC-Request-Number
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
      .addAVP(create_string_avp(30, "internet.sberbank-tele.com", std::nullopt, true)) // Called-Station-Id
      .addAVP(create_ipv4_avp(
        501,
        request.access_network_charging_ip_address,
        10415,
        true))
        //< Access-Network-Charging-Address
      .addAVP(create_ipv4_4bytes_avp(8, request.framed_ip_address, std::nullopt, true)) // Framed-IP-Address
      .addAVP(create_int32_avp(1009, 1, 10415, true)) // Online
      .addAVP(create_int32_avp(1008, 1, 10415, true)) // Offline
      .addAVP(create_avp( //< Access-Network-Charging-Identifier-Gx(1022)
        1022,
        Diameter::AVP::Data()
        .addAVP(create_octets_avp(503, uint32_to_buf_(request.charging_id), 10415, true))
        //< Access-Network-Charging-Identifier-Value(503)
        ,
        10415,
        true
        ))
      .addAVP(create_ipv4_4bytes_avp(6, request.sgsn_ip_address, 10415, false)) // 3GPP-SGSN-Address(6)
      .addAVP(create_ipv4_avp(1050, request.sgsn_ip_address, 10415, false)) // AN-GW-Address(1050)=3GPP-SGSN-Address
      .addAVP(create_uint32_avp(1032, request.rat_type, 10415, false)) // RAT-Type
      .addAVP(create_uint32_avp(1024, 1, 10415, true)) // Network-Request-Support
      .addAVP(create_string_avp(18, request.mcc_mnc, 10415, false)) // 3GPP-SGSN-MCC-MNC(18)
      .addAVP(create_octets_avp(22, ByteArray(USER_LOCATION, sizeof(USER_LOCATION)), 10415, false)) // 3GPP-User-Location-Info
      // < REVIEW content
      .addAVP(create_uint16_avp(
        23,
        static_cast<uint16_t>(request.timezone) << 8 | 0, //< Adjustment=0
        10415,
        false
      )) // 3GPP-MS-TimeZone
      // Subscription-Id with IMSI
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
          .addAVP(create_string_avp(444, request.msisdn)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 1)) // Subscription-Id-Type = END_USER_IMSI
          .addAVP(create_string_avp(444, request.imsi)), // Subscription-Id-Data
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

    if (!request.imei.empty())
    {
      packet.addAVP(
        create_avp(
          458, // User-Equipment-Info(458)
          Diameter::AVP::Data()
            .addAVP(create_uint32_avp(459, 0, std::nullopt, false)) // User-Equipment-Info-Type(459) = IMEISV
            .addAVP(create_string_avp(460, request.imei, std::nullopt, false)) // User-Equipment-Info-Type(459)
          ,
          std::nullopt,
          false
        )
      );
    }
    return packet
      .addAVP(create_int32_avp(416, 1, std::nullopt, true)) // CC-Request-Type
      .updateLength()
      .deploy();
  }

  ByteArray
  DiameterSession::generate_gx_update_(
    const Request& request,
    const GxUpdateRequest& update_request)
    const
  {
    auto packet = generate_base_gx_packet_(request);

    packet.addAVP(create_int32_avp(416, 2)) // CC-Request-Type
      ;

    for (const auto& usage_monitoring : update_request.usage_monitorings)
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

    return packet
      .updateLength()
      .deploy();
  }

  ByteArray
  DiameterSession::generate_gx_terminate_(
    const Request& request,
    const GxTerminateRequest& terminate_request)
    const
  {
    return generate_base_gx_packet_(request)
      .addAVP(create_uint32_avp(1006, terminate_request.event_trigger, 10415, true)) // Event-Trigger(1006)
      .addAVP(create_uint32_avp(295, terminate_request.termination_cause, std::nullopt, true)) // Termination-Cause(295)
      .addAVP(create_int32_avp(416, 3)) // CC-Request-Type
      .updateLength()
      .deploy();
  }

  ByteArray
  DiameterSession::generate_watchdog_packet_() const
  {
    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(Diameter::Packet::Header::Flags())
          .setCommandCode(280)
          .setApplicationId(0)
          .setHBHIdentifier(0x7ddf9367)
          .setETEIdentifier(0xc15ecb12)
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

  ByteArray
  DiameterSession::generate_base_gy_packet_(const GyRequest& request) const
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
          .setApplicationId(application_id_)
          .setHBHIdentifier(0x7ddf9367)
          .setETEIdentifier(0xc15ecb12)
      );

    packet
      .addAVP(create_string_avp(263, session_id_, std::nullopt, true)) // Session-Id
      .addAVP(create_uint32_avp(258, application_id_, std::nullopt, true)) // Auth-Application-Id
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
      .addAVP(create_uint32_avp(415, ++request_i_, std::nullopt, true)) // CC-Request-Number
      .addAVP(create_uint32_avp(278, origin_state_id_, std::nullopt, true)) // Origin-State-Id
      .addAVP(create_uint32_avp(55, Gears::Time::get_time_of_day().tv_sec, std::nullopt, true)) // Event-Timestamp(55)
      // Subscription-Id with IMSI
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
          .addAVP(create_string_avp(444, request.msisdn)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 1)) // Subscription-Id-Type = END_USER_IMSI
          .addAVP(create_string_avp(444, request.imsi)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_uint32_avp(455, 1, std::nullopt, true)) // Multiple-Services-Indicator(455)
      ;

    for (auto rating_group : request.rating_groups)
    {
      packet.addAVP(
        create_avp(
          456, // Multiple-Services-Credit-Control(456)
          Diameter::AVP::Data()
            .addAVP(create_uint32_avp(432, rating_group, std::nullopt, true)) // Rating-Group(432)
            .addAVP(create_octets_avp(437, ByteArray(), std::nullopt, true)) // Requested-Service-Unit(437)
          ,
          std::nullopt,
          true
        )
      );
    }

    if (!request.imei.empty())
    {
      packet.addAVP(
        create_avp(
          458, // User-Equipment-Info(458)
          Diameter::AVP::Data()
            .addAVP(create_uint32_avp(459, 0, std::nullopt, false)) // User-Equipment-Info-Type(459) = IMEISV
            .addAVP(create_string_avp(460, request.imei, std::nullopt, false)) // User-Equipment-Info-Type(459)
          ,
          std::nullopt,
          false
        )
      );
    }

    const uint8_t USER_LOCATION[] = {
      0x82, // Geographic Location Type: TAI and ECGI (130)
      0x52, 0xf0, 0x02, 0x6c, 0xf6,
      0x52, 0xf0, 0x02, 0x07, 0xad, 0xde, 0x51
    };

    packet.addAVP(
      create_avp(
        873, // Service-Information(873)
        Diameter::AVP::Data().addAVP(
          create_avp(
            874, // PS-Information(874)
            Diameter::AVP::Data()
              .addAVP(create_uint32_avp(2, request.charging_id, 10415, false)) // 3GPP-Charging-Id(2)
              .addAVP(create_uint32_avp(3, 0, 10415, false)) // 3GPP-PDP-Type(3)=IPv4
              .addAVP(create_ipv4_avp(1227, request.framed_ip_address, 10415, true))
                // PDP-Address(1227)=framed_ip_address
              .addAVP(create_string_avp(5, request.gprs_negotiated_qos_profile, 10415, false))
                // 3GPP-GPRS-Negotiated-QoS-Profile(5)
              .addAVP(create_ipv4_avp(1228, request.sgsn_ip_address, 10415, true)) // SGSN-Address(1228)
              .addAVP(create_ipv4_avp(847, request.access_network_charging_ip_address, 10415, true)) // GGSN-Address(847)
              .addAVP(create_ipv4_avp(846, request.sgsn_ip_address, 10415, true)) // CG-Address(846) // ???
              .addAVP(create_string_avp(8, request.mcc_mnc, 10415, false)) // 3GPP-SGSN-MCC-MNC(8)
              .addAVP(create_string_avp(9, request.mcc_mnc, 10415, false)) // 3GPP-GGSN-MCC-MNC(9)
              .addAVP(create_string_avp(10, "5", 10415, false)) // 3GPP-NSAPI(10)
              .addAVP(create_string_avp(30, "internet.sberbank-tele.com", std::nullopt, true)) // Called-Station-Id(30)
              .addAVP(create_string_avp(12, "0", 10415, false)) // 3GPP-Selection-Mode(12)
              .addAVP(create_string_avp(13, "0800", 10415, false)) // 3GPP-Charging-Characteristics(13)
              .addAVP(create_string_avp(18, request.mcc_mnc, 10415, false)) // 3GPP-SGSN-MCC-MNC(18)
              .addAVP(create_octets_avp(22, ByteArray(USER_LOCATION, sizeof(USER_LOCATION)), 10415, false))
              // 3GPP-User-Location-Info(22)
              .addAVP(create_uint16_avp(
                23,
                static_cast<uint16_t>(request.timezone) << 8 | 0, //< Adjustment=0
                10415,
                false
              )) // 3GPP-MS-TimeZone
              .addAVP(create_uint32_avp(21, request.rat_type, 10415, false)) // 3GPP-RAT-Type(21)
              .addAVP(create_uint32_avp(1247, 0, 10415, false)) // PDP-Context-Type(1247)=PRIMARY
              .addAVP(create_uint32_avp(2050, request.charging_id, 10415, true)) // PDN-Connection-Charging-ID(2050)
              .addAVP(create_uint32_avp(2047, 2, 10415, true))// Serving-Node-Type(2047)=GTPSGW
              .addAVP(create_string_avp(1004, "up_bypass", 10415, true)) // Charging-Rule-Base-Name(1004)=up_bypass
            ,
            10415,
            true
          )
        ),
        10415,
        true
      )
    );

    return packet
      .addAVP(create_int32_avp(416, 1, std::nullopt, true)) // CC-Request-Type
      .updateLength()
      .deploy();
  }

  ByteArray DiameterSession::uint32_to_buf_(uint32_t val)
  {
    const uint8_t BUF[] = {
      static_cast<uint8_t>((val >> 24) & 0xFF),
      static_cast<uint8_t>((val >> 16) & 0xFF),
      static_cast<uint8_t>((val >> 8) & 0xFF),
      static_cast<uint8_t>(val & 0xFF)
    };

    return ByteArray(BUF, sizeof(BUF));
  }

  Diameter::Packet DiameterSession::generate_base_gx_packet_(const Request& request)
    const
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
          .setApplicationId(application_id_)
          .setHBHIdentifier(0x7ddf9367)
          .setETEIdentifier(0xc15ecb12)
      );

    packet
      .addAVP(create_string_avp(263, session_id_, std::nullopt, true)) // Session-Id
      .addAVP(create_uint32_avp(258, application_id_, std::nullopt, true)) // Auth-Application-Id
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

    return packet
      .addAVP(create_uint32_avp(415, ++request_i_, std::nullopt, true)) // CC-Request-Number
      .addAVP(create_uint32_avp(278, origin_state_id_, std::nullopt, true)) // Origin-State-Id
      .addAVP(create_string_avp(30, "internet.sberbank-tele.com", std::nullopt, true)) // Called-Station-Id
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
          .addAVP(create_string_avp(444, request.msisdn)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      .addAVP(create_avp( // Subscription-Id
        443,
        Diameter::AVP::Data()
          .addAVP(create_int32_avp(450, 1)) // Subscription-Id-Type = END_USER_IMSI
          .addAVP(create_string_avp(444, request.imsi)), // Subscription-Id-Data
        std::nullopt,
        true
        ))
      ;
  }

  ByteArray
  DiameterSession::generate_exchange_packet_() const
  {
    // 10.77.208.36
    // 10.77.208.68
    static const uint8_t SOURCE_ADDR1[] = { 0, 0x1, 10, 77, 208, 36 };
    static const uint8_t SOURCE_ADDR2[] = { 0, 0x1, 10, 77, 208, 68 };
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
          .setHBHIdentifier(0x00000ad1)
          .setETEIdentifier(0x00000ad1)
       );

    if (destination_host_.has_value())
    {
      packet.addAVP(create_string_avp(293, *destination_host_));
    }

    /*
    if (destination_realm_.has_value())
    {
      packet.addAVP(create_string_avp(283, *destination_realm_));
    }
    */

    if (!source_addresses_.empty())
    {
      for (const auto& source_addr : source_addresses_)
      {
        packet.addAVP(create_ipv4_avp(257, source_addr)); // Host-IP-Address(257)
      }
    }
    else
    {
      for (const auto& local_endpoint : local_endpoints_)
      {
        uint32_t addr = string_to_ipv4_address(local_endpoint.host);
        packet.addAVP(create_ipv4_avp(257, addr));
        // Host-IP-Address(257)
      }
    }

    return packet
      .addAVP(create_string_avp(264, origin_host_)) // Origin-Host
      .addAVP(create_string_avp(296, origin_realm_)) // Origin-Realm
      .addAVP(create_uint32_avp(266, 2011)) // Vendor-Id
      //.addAVP(create_string_avp(269, "3GPP Gx")) // Product-Name
      .addAVP(create_string_avp(269, product_name_)) // "Diameter Credit Control Application")) // Product-Name
      .addAVP(create_uint32_avp(299, 0)) // Inband-Security-Id
      .addAVP(create_uint32_avp(258, application_id_)) // Auth-Application-Id

      .updateLength()
      .deploy()
      ;
  }
}
