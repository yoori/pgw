#pragma once

#include <string>
#include <optional>
#include <unordered_set>
#include <mutex>
#include <condition_variable>

#include <gears/Exception.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/CompositeActiveObject.hpp>

#include <Diameter/Packet.hpp>

#include "Logger.hpp"
#include "NetworkUtils.hpp"
#include "BaseConnection.hpp"
#include "SCTPConnection.hpp"
#include "UserSessionTraits.hpp"

namespace dpi
{
  // DiameterSession
  /*
  class DiameterMessageContainer: public Gears::CompositeActiveObject
  {
  };
  */

  class DiameterSession: public Gears::CompositeActiveObject
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(DiameterError, Exception);

    struct Request
    {
      UserSessionTraits user_session_traits;

      std::string to_string() const;
    };

    struct GyRequest: public Request
    {
      struct UsageRatingGroup
      {
        UsageRatingGroup() {}

        UsageRatingGroup(unsigned long rating_group_id_val, uint64_t total_octets_val = 0)
          : rating_group_id(rating_group_id_val),
            total_octets(total_octets_val)
        {}

        unsigned long rating_group_id = 0;
        uint64_t total_octets = 0;
      };

      std::vector<UsageRatingGroup> usage_rating_groups;
    };

    struct GxUpdateRequest
    {
      struct UsageMonitoring
      {
        UsageMonitoring() {}

        UsageMonitoring(
          unsigned long monitoring_key_val,
          uint64_t total_octets_val,
          unsigned long usage_monitoring_level_val = 1 //< PCC_RULE_LEVEL
          )
          : monitoring_key(monitoring_key_val),
            total_octets(total_octets_val),
            usage_monitoring_level(usage_monitoring_level_val)
        {}

        unsigned long monitoring_key = 0;
        uint64_t total_octets = 0;
        unsigned long usage_monitoring_level = 1;
      };

      std::vector<UsageMonitoring> usage_monitorings;

      std::string to_string() const;
    };

    struct GxTerminateRequest: public GxUpdateRequest
    {
      unsigned long event_trigger = 26; // TAI_CHANGE
      unsigned long termination_cause = 1; // DIAMETER_LOGOUT
    };

    struct GxResponse
    {
      unsigned int result_code = 0;
    };

    struct GxInitResponse: public GxResponse
    {
      std::unordered_set<std::string> charging_rule_names;
    };

    struct GxUpdateResponse: public GxResponse
    {};

    struct GxTerminateResponse: public GxResponse
    {};

    struct GyResponse
    {
      struct RatingGroupLimit
      {
        unsigned long rating_group_id = 0;
        std::optional<unsigned long> max_bps;
        std::optional<uint64_t> cc_total_octets;
        Gears::Time validity_time;
        unsigned long result_code = 0;

        std::string to_string() const;
      };

      unsigned int result_code = 0;
      std::vector<RatingGroupLimit> rating_group_limits;
    };

    DiameterSession(
      dpi::LoggerPtr logger,
      BaseConnectionPtr connection,
      std::string origin_host,
      std::string origin_realm,
      std::optional<std::string> destination_host,
      std::optional<std::string> destination_realm,
      unsigned long auth_application_id,
      std::string product_name,
      const std::vector<std::string>& source_addresses = std::vector<std::string>()
      );

    virtual ~DiameterSession();

    void deactivate_object() override;

    void set_logger(dpi::LoggerPtr logger);

    // connect if isn't connected
    //void connect();

    GxInitResponse send_gx_init(const Request& request);

    GxUpdateResponse send_gx_update(
      const Request& request,
      const GxUpdateRequest& update_request);

    GxTerminateResponse send_gx_terminate(
      const Request& request,
      const GxTerminateRequest& terminate_request);

    GyResponse send_gy_init(const GyRequest& request);

    GyResponse send_gy_update(const GyRequest& request);

    GyResponse send_gy_terminate(const GyRequest& request);

    static void make_exchange(
      BaseConnection& connection,
      const std::string& origin_host,
      const std::string& origin_realm,
      const std::optional<std::string>& destination_host,
      const std::optional<std::string>& destination_realm,
      const std::string& product_name,
      const std::vector<uint32_t>& applications,
      const std::vector<std::string>& source_addresses);

    void set_application(unsigned long application_id);

  protected:
    class ReadResponsesTask;

  private:
    using PacketGenerator = std::function<std::pair<unsigned int, ByteArray>()>;

  private:
    static ByteArray generate_exchange_packet_(
      const std::string& origin_host,
      const std::string& origin_realm,
      const std::optional<std::string>& destination_host,
      const std::optional<std::string>& destination_realm,
      const std::string& product_name,
      const std::vector<uint32_t>& applications,
      const std::vector<std::string>& source_addresses);

    std::pair<unsigned int, ByteArray>
    generate_gx_init_(const Request& request) const;

    std::pair<unsigned int, ByteArray>
    generate_gx_update_(
      const Request& request,
      const GxUpdateRequest& update_request) const;

    std::pair<unsigned int, ByteArray>
    generate_gx_terminate_(
      const Request& request,
      const GxTerminateRequest& terminate_request) const;

    std::pair<unsigned int, Diameter::Packet>
    generate_base_gx_packet_(const Request& request)
      const;

    std::pair<unsigned int, ByteArray>
    generate_gy_init_(const GyRequest& request) const;

    std::pair<unsigned int, ByteArray>
    generate_gy_update_(const GyRequest& request) const;

    std::pair<unsigned int, ByteArray>
    generate_gy_terminate_(const GyRequest& request) const;

    std::pair<unsigned int, Diameter::Packet>
    generate_base_gy_packet_(const GyRequest& request) const;

    ByteArray
    generate_watchdog_packet_() const;

    ByteArray
    generate_rar_response_packet_(const std::string& session_id) const;

    std::pair<std::optional<uint32_t>, std::shared_ptr<Diameter::Packet>>
    send_and_read_response_i_(
      PacketGenerator packet_generator);

    //static Diameter::Packet read_packet_(BaseConnection::Lock& connection);

    bool is_connected_(int socket_fd);

    //void make_exchange_i_();

    static ByteArray uint32_to_buf_(uint32_t val);

    // responses reading thread
    void responses_reading_();

    void
    process_input_request_(const Diameter::Packet& request);

    std::shared_ptr<Diameter::Packet>
    wait_response_(std::optional<uint32_t> request_i = std::nullopt);

    void
    parse_gy_response_(GyResponse& gy_response, Diameter::Packet& response);

  private:
    dpi::LoggerPtr logger_;
    BaseConnectionPtr connection_;
    Gears::TaskRunner_var task_runner_;

    const int RETRY_COUNT_ = 1;
    unsigned int gx_application_id_;
    unsigned int gy_application_id_;
    const std::string product_name_;
    std::vector<uint32_t> source_addresses_;
    const uint32_t origin_state_id_;

    std::string origin_host_;
    std::string origin_realm_;
    std::optional<std::string> destination_host_;
    std::optional<std::string> destination_realm_;
    std::string session_id_;
    //unsigned int service_id_;
    mutable unsigned long request_i_;
    bool exchange_done_ = false;

    // responses (other thread fill it)
    std::mutex responses_lock_;
    std::condition_variable responses_cond_;
    std::unordered_map<unsigned long, std::shared_ptr<Diameter::Packet>> responses_;
    std::shared_ptr<Diameter::Packet> last_response_;
  };

  using DiameterSessionPtr = std::shared_ptr<DiameterSession>;
};

namespace dpi
{
  inline std::string
  DiameterSession::GyResponse::RatingGroupLimit::to_string() const
  {
    std::string res;
    res += "{";
    res += "rating_group_id = " + std::to_string(rating_group_id);
    res += ", max_bps = " + (max_bps.has_value() ? std::to_string(*max_bps) : std::string("null"));
    res += ", cc_total_octets = " + (
      cc_total_octets.has_value() ? std::to_string(*cc_total_octets) : std::string("null"));
    res += ", validity_time = " + std::to_string(validity_time.tv_sec);
    res += ", result_code = " + std::to_string(result_code);
    res += "}";
    return res;
  }

  inline std::string
  DiameterSession::Request::to_string() const
  {
    std::string res;
    res += std::string("{user_session_traits = ") + user_session_traits.to_string() + "}";
    return res;
  }

  inline std::string
  DiameterSession::GxUpdateRequest::to_string() const
  {
    std::string res;
    res += "{";
    for (const auto& usage_monitoring: usage_monitorings)
    {
      res += "(mk = " + std::to_string(usage_monitoring.monitoring_key) +
        ", total-octets = " + std::to_string(usage_monitoring.total_octets) + ")";
    }
    res += "}";

    return res;
  }
}

