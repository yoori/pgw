#pragma once

#include <string>
#include <optional>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <vector>

#include <gears/Exception.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/CompositeActiveObject.hpp>
#include <gears/Hash.hpp>
#include <gears/HashTable.hpp>

#include <Diameter/Packet.hpp>

#include "Types.hpp"
#include "Logger.hpp"
#include "NetworkUtils.hpp"
#include "BaseConnection.hpp"
#include "SCTPConnection.hpp"
#include "UserSessionTraits.hpp"
#include "DiameterDictionary.hpp"
#include "DiameterPassAttribute.hpp"
#include "OctetStats.hpp"

namespace dpi
{
  // DiameterSession
  class DiameterSession
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(DiameterError, Exception);

    // requests
    struct Request
    {
      UserSessionTraits user_session_traits;

      unsigned long application_id = 0;
      std::string session_id_suffix;
      unsigned int request_id = 0;

      std::string to_string() const;
    };

    struct GyRequest: public Request
    {
      struct UsageRatingGroup: public OctetStats
      {
        UsageRatingGroup() {}

        UsageRatingGroup(
          unsigned long rating_group_id_val,
          const OctetStats& octet_stats = OctetStats(),
          const std::optional<UsageReportingReason>& reporting_reason_val)
          : OctetStats(octet_stats),
            rating_group_id(rating_group_id_val),
            reporting_reason(reporting_reason_val)
        {}

        unsigned long rating_group_id = 0;
        std::optional<UsageReportingReason> reporting_reason;
        //< If limit isn't reached(null) we push OTHER_QUOTA_TYPE
      };

      std::string reason;
      std::vector<UsageRatingGroup> usage_rating_groups;

      std::string to_string() const;
    };

    struct GxUpdateRequest
    {
      struct UsageMonitoring: public OctetStats
      {
        UsageMonitoring() {}

        UsageMonitoring(
          unsigned long monitoring_key_val,
          const OctetStats& octet_stats = OctetStats(),
          unsigned long usage_monitoring_level_val = 1 //< PCC_RULE_LEVEL
          )
          : OctetStats(octet_stats),
            monitoring_key(monitoring_key_val),
            usage_monitoring_level(usage_monitoring_level_val)
        {}

        unsigned long monitoring_key = 0;
        unsigned long usage_monitoring_level = 1;
      };

      std::vector<UsageMonitoring> usage_monitorings;
      std::unordered_set<std::string> not_found_charging_rule_names;

      std::string to_string() const;
    };

    struct GxTerminateRequest: public GxUpdateRequest
    {
      unsigned long event_trigger = 26; // TAI_CHANGE
      unsigned long termination_cause = 1; // DIAMETER_LOGOUT
    };

    // responses
    struct GxResponse
    {
      unsigned int result_code = 0;

      std::string to_string() const;
    };

    struct GxInitResponse: public GxResponse
    {
      std::unordered_set<std::string> install_charging_rule_names;
      std::unordered_set<std::string> remove_charging_rule_names;

      std::string to_string() const;
    };

    struct GxUpdateResponse: public GxInitResponse
    {
    };

    struct GxTerminateResponse: public GxResponse
    {
    };

    struct GyResponse
    {
      struct RatingGroupLimit
      {
        unsigned long rating_group_id = 0;
        std::optional<unsigned long> max_bps;
        std::optional<uint64_t> cc_total_octets;
        std::optional<uint64_t> octets_threshold;
        Gears::Time validity_time;
        unsigned long result_code = 0;

        std::string to_string() const;
      };

      unsigned int result_code = 0;
      std::vector<RatingGroupLimit> rating_group_limits;

      std::string to_string() const;
    };

    using RequestProcessor = std::function<void(const Diameter::Packet& packet)>;

  public:
    virtual void
    set_request_processor(RequestProcessor request_processor) = 0;

    virtual void
    send_packet(const ByteArray& send_packet) = 0;

    virtual GxInitResponse
    send_gx_init(const Request& request) = 0;

    virtual GxUpdateResponse
    send_gx_update(
      const Request& request,
      const GxUpdateRequest& update_request) = 0;

    virtual GxTerminateResponse
    send_gx_terminate(
      const Request& request,
      const GxTerminateRequest& terminate_request) = 0;

    virtual GyResponse
    send_gy_init(const GyRequest& request) = 0;

    virtual GyResponse
    send_gy_update(const GyRequest& request) = 0;

    virtual GyResponse
    send_gy_terminate(const GyRequest& request) = 0;
  };

  using DiameterSessionPtr = std::shared_ptr<DiameterSession>;

  // SCTPDiameterSession
  class SCTPDiameterSession:
    public DiameterSession,
    public Gears::CompositeActiveObject
  {
  public:
    SCTPDiameterSession(
      LoggerPtr logger,
      const DiameterDictionary& diameter_dictionary,
      BaseConnectionPtr connection,
      std::string origin_host,
      std::string origin_realm,
      std::optional<std::string> destination_host,
      std::optional<std::string> destination_realm,
      unsigned long auth_application_id,
      std::string product_name,
      RequestProcessor request_processor,
      const std::vector<std::string>& source_addresses,
      std::vector<DiameterPassAttribute> gx_pass_attributes,
      std::vector<DiameterPassAttribute> gy_pass_attributes
      );

    virtual ~SCTPDiameterSession();

    void deactivate_object() override;

    void set_logger(dpi::LoggerPtr logger);

    virtual void
    set_request_processor(RequestProcessor request_processor) override;

    void
    send_packet(const ByteArray& send_packet) override;

    GxInitResponse
    send_gx_init(const Request& request) override;

    GxUpdateResponse
    send_gx_update(
      const Request& request,
      const GxUpdateRequest& update_request) override;

    GxTerminateResponse
    send_gx_terminate(
      const Request& request,
      const GxTerminateRequest& terminate_request) override;

    GyResponse
    send_gy_init(const GyRequest& request) override;

    GyResponse
    send_gy_update(const GyRequest& request) override;

    GyResponse
    send_gy_terminate(const GyRequest& request) override;

    static void make_exchange(
      BaseConnection& connection,
      const std::string& origin_host,
      const std::string& origin_realm,
      const std::optional<std::string>& destination_host,
      const std::optional<std::string>& destination_realm,
      const std::string& product_name,
      const std::vector<uint32_t>& applications,
      const std::vector<std::string>& source_addresses);

    static void
    get_charging_rules(
      std::unordered_set<std::string>& install_charging_rule_names,
      std::unordered_set<std::string>& remove_charging_rule_names,
      const Diameter::Packet& response);

  protected:
    class ReadResponsesTask;

    struct RequestKey
    {
      RequestKey();
      
      RequestKey(std::string session_id_val, unsigned int request_i_val);

      bool operator==(const RequestKey& right) const;

      unsigned long hash() const;

      std::string to_string() const;

      const std::string session_id;
      const unsigned int request_i = 0;

    protected:
      void calc_hash_();

    protected:
      unsigned long hash_;
    };

  private:
    using PacketGenerator = std::function<std::pair<RequestKey, ByteArray>()>;

  private:
    static ByteArray generate_exchange_packet_(
      const std::string& origin_host,
      const std::string& origin_realm,
      const std::optional<std::string>& destination_host,
      const std::optional<std::string>& destination_realm,
      const std::string& product_name,
      const std::vector<uint32_t>& applications,
      const std::vector<std::string>& source_addresses);

    std::pair<RequestKey, ByteArray>
    generate_gx_init_(const Request& request) const;

    std::pair<RequestKey, ByteArray>
    generate_gx_update_(
      const Request& request,
      const GxUpdateRequest& update_request) const;

    std::pair<RequestKey, ByteArray>
    generate_gx_terminate_(
      const Request& request,
      const GxTerminateRequest& terminate_request) const;

    std::pair<RequestKey, Diameter::Packet>
    generate_base_gx_packet_(const Request& request)
      const;

    std::pair<RequestKey, ByteArray>
    generate_gy_init_(const GyRequest& request) const;

    std::pair<RequestKey, ByteArray>
    generate_gy_update_(const GyRequest& request) const;

    std::pair<RequestKey, ByteArray>
    generate_gy_terminate_(const GyRequest& request) const;

    std::pair<RequestKey, Diameter::Packet>
    generate_base_gy_packet_(
      const GyRequest& request,
      const std::optional<UsageReportingReason>& reporting_reason) const;

    ByteArray
    generate_watchdog_packet_(
      uint32_t hbh_identifier,
      uint32_t ete_identifier) const;

    std::tuple<std::optional<uint32_t>, std::shared_ptr<Diameter::Packet>, RequestKey>
    send_and_read_response_i_(PacketGenerator packet_generator);

    //static Diameter::Packet read_packet_(BaseConnection::Lock& connection);

    bool is_connected_(int socket_fd);

    //void make_exchange_i_();

    static ByteArray uint32_to_buf_(uint32_t val);

    // responses reading thread
    void responses_reading_();

    void
    process_input_request_(const Diameter::Packet& request);

    std::shared_ptr<Diameter::Packet>
    wait_response_(const RequestKey& request_key);

    std::shared_ptr<Diameter::Packet>
    wait_response_();

    void
    parse_gy_response_(GyResponse& gy_response, Diameter::Packet& response);

    static void
    fill_gx_stat_update_(
      Diameter::Packet& packet,
      const SCTPDiameterSession::GxUpdateRequest& gx_update_request);

    std::string
    get_session_id_(const std::string& session_id_suffix) const;

  private:
    dpi::LoggerPtr logger_;
    const DiameterDictionary& diameter_dictionary_;
    BaseConnectionPtr connection_;
    Gears::TaskRunner_var task_runner_;
    Gears::TaskRunner_var response_process_task_runner_;

    const int RETRY_COUNT_ = 1;
    unsigned int gx_application_id_;
    unsigned int gy_application_id_;
    const std::string product_name_;
    std::vector<uint32_t> source_addresses_;
    RequestProcessor request_processor_;

    std::vector<DiameterPassAttribute> gx_pass_attributes_;
    std::vector<DiameterPassAttribute> gy_pass_attributes_;

    const uint32_t origin_state_id_;

    std::string origin_host_;
    std::string origin_realm_;
    std::optional<std::string> destination_host_;
    std::optional<std::string> destination_realm_;
    //std::string session_id_;
    //unsigned int service_id_;
    //mutable unsigned long request_i_;
    bool exchange_done_ = false;

    // responses (other thread fill it)
    std::mutex responses_lock_;
    std::condition_variable responses_cond_;
    Gears::GnuHashSet<RequestKey> wait_responses_;
    Gears::HashTable<RequestKey, std::shared_ptr<Diameter::Packet>> responses_;
    std::shared_ptr<Diameter::Packet> last_response_;
  };
};

namespace dpi
{
  // SCTPDiameterSession::RequestKey
  inline
  SCTPDiameterSession::RequestKey::RequestKey()
    : hash_(0)
  {}

  inline
  SCTPDiameterSession::RequestKey::RequestKey(std::string session_id_val, unsigned int request_i_val)
    : session_id(session_id_val),
      request_i(request_i_val),
      hash_(0)
  {
    calc_hash_();
  }

  inline bool
  SCTPDiameterSession::RequestKey::operator==(const RequestKey& right) const
  {
    return session_id == right.session_id && request_i == right.request_i;
  }

  inline unsigned long
  SCTPDiameterSession::RequestKey::hash() const
  {
    return hash_;
  }

  inline std::string
  SCTPDiameterSession::RequestKey::to_string() const
  {
    return std::string("{session_id = ") + session_id +
      ", request_i = " + std::to_string(request_i) +
      "}";
  }

  inline void
  SCTPDiameterSession::RequestKey::calc_hash_()
  {
    Gears::Murmur64Hash hasher(hash_);
    hash_add(hasher, session_id);
    hash_add(hasher, request_i);
  }

  // SCTPDiameterSession::GyResponse::RatingGroupLimit
  inline std::string
  SCTPDiameterSession::GyResponse::RatingGroupLimit::to_string() const
  {
    std::string res;
    res += "{";
    res += "\"rating_group_id\": " + std::to_string(rating_group_id);
    res += ", \"max_bps\": " + (max_bps.has_value() ? std::to_string(*max_bps) : std::string("null"));
    res += ", \"cc_total_octets\": " + (
      cc_total_octets.has_value() ? std::to_string(*cc_total_octets) : std::string("null"));
    res += ", \"validity_time\": " + std::to_string(validity_time.tv_sec);
    res += ", \"result_code\": " + std::to_string(result_code);
    res += "}";
    return res;
  }

  inline std::string
  SCTPDiameterSession::Request::to_string() const
  {
    std::string res;
    res += std::string("{user_session_traits = ") + user_session_traits.to_string() + "}";
    return res;
  }

  inline std::string
  SCTPDiameterSession::GxUpdateRequest::to_string() const
  {
    std::string res;
    res += "{\"usage_monitorings\": [";
    for (const auto& usage_monitoring: usage_monitorings)
    {
      res += std::string("{") +
        "\"mk\": \"" + std::to_string(usage_monitoring.monitoring_key) + "\"," +
        "\"total-octets\": " + std::to_string(usage_monitoring.total_octets) +
        "}";
    }
    res += "]}";

    return res;
  }

  inline std::string
  SCTPDiameterSession::GyRequest::to_string() const
  {
    std::string res;
    res += std::string("{\"user_session_traits\": ") + user_session_traits.to_string() +
      ", \"usage_rating_groups\": [";
    for (auto it = usage_rating_groups.begin(); it != usage_rating_groups.end(); ++it)
    {
      res += std::string("{") +
        "\"rg_id\":" + std::to_string(it->rating_group_id) + "," +
        "\"total_octets\": " + std::to_string(it->total_octets) +
        "}";
    }
    res += "]}";
    return res;
  }

  inline std::string
  SCTPDiameterSession::GxResponse::to_string() const
  {
    std::string res;
    res += std::string("{\"result_code\": ") + std::to_string(result_code) + "}";
    return res;
  }

  inline std::string
  SCTPDiameterSession::GxInitResponse::to_string() const
  {
    std::string res;
    res += std::string("{\"result_code\": ") + std::to_string(result_code) +
      ", \"install_charging_rule_names\": ";
    for (auto it = install_charging_rule_names.begin(); it != install_charging_rule_names.end(); ++it)
    {
      res += (it != install_charging_rule_names.begin() ? ", " : "") + *it;
    }
    res += ", \"remove_charging_rule_names\": ";
    for (auto it = remove_charging_rule_names.begin(); it != remove_charging_rule_names.end(); ++it)
    {
      res += (it != remove_charging_rule_names.begin() ? ", " : "") + *it;
    }
    res += "}";
    return res;
  }

  inline std::string
  SCTPDiameterSession::GyResponse::to_string() const
  {
    std::string res;
    res += std::string("{\"result_code\": ") + std::to_string(result_code) +
      ", \"rating_group_limits\": [";
    for (auto it = rating_group_limits.begin(); it != rating_group_limits.end(); ++it)
    {
      res += (it != rating_group_limits.begin() ? ", " : "") + it->to_string();
    }
    res += "]}";
    return res;
  }
}
