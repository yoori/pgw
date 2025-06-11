#pragma once

#include <string>
#include <optional>
#include <mutex>

#include <gears/Exception.hpp>

#include <Diameter/Packet.hpp>

#include "Logger.hpp"
#include "NetworkUtils.hpp"

namespace dpi
{
  class DiameterSession
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(NetworkError, Exception);
    DECLARE_EXCEPTION(ConnectionClosedOnRead, NetworkError);
    DECLARE_EXCEPTION(DiameterError, Exception);

    struct Endpoint
    {
      Endpoint() {};

      Endpoint(std::string host_val, int port_val)
        : host(std::move(host_val)), port(port_val)
      {}

      std::string host;
      int port = 0;
    };

    struct Request
    {
      std::string msisdn;
      std::string imsi;
      std::string imei;
      uint32_t framed_ip_address = 0;
      uint32_t nas_ip_address = 0;
      uint32_t rat_type = 0;
      unsigned char timezone = 0; //< RADIUS: Vendor-Specific.3GPP.MS-TimeZone.TZ
      std::string mcc_mnc;
      uint32_t sgsn_ip_address = 0; //< RADIUS: Vendor-Specific.3GPP.SGSN-Address
      uint32_t access_network_charging_ip_address = 0;
      //< RADIUS: Vendor-Specific.3GPP.Access-Network-Charging-Address
      uint32_t charging_id = 0; //< RADIUS: Vendor-Specific.3GPP.Charging-ID
      std::string gprs_negotiated_qos_profile; //< RADIUS

      std::string to_string() const;
    };

    struct GyRequest: public Request
    {
      std::vector<unsigned long> rating_groups;
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
    {};

    struct GxUpdateResponse: public GxResponse
    {};

    struct GxTerminateResponse: public GxResponse
    {};

    struct GyResponse
    {
      unsigned int result_code = 0;
    };

    DiameterSession(
      dpi::LoggerPtr logger,
      std::vector<Endpoint> local_endpoints,
      std::vector<Endpoint> connect_endpoints,
      std::string origin_host,
      std::string origin_realm,
      std::optional<std::string> destination_host,
      std::optional<std::string> destination_realm,
      unsigned long auth_application_id,
      std::string product_name,
      bool keep_open_connection = false,
      const std::vector<std::string>& source_addresses = std::vector<std::string>()
      );

    virtual ~DiameterSession();

    void set_logger(dpi::LoggerPtr logger);

    void open();

    GxInitResponse send_gx_init(const Request& request);

    GxUpdateResponse send_gx_update(
      const Request& request,
      const GxUpdateRequest& update_request);

    GxTerminateResponse send_gx_terminate(
      const Request& request,
      const GxTerminateRequest& terminate_request);

    GyResponse send_gy_init(const GyRequest& request);

  private:
    ByteArray generate_exchange_packet_() const;

    ByteArray generate_gx_init_(const Request& request) const;

    ByteArray generate_gx_update_(
      const Request& request,
      const GxUpdateRequest& update_request) const;

    ByteArray generate_gx_terminate_(
      const Request& request,
      const GxTerminateRequest& terminate_request) const;

    Diameter::Packet generate_base_gx_packet_(const Request& request)
      const;

    ByteArray generate_gy_init_(const GyRequest& request) const;

    ByteArray generate_base_gy_packet_(const GyRequest& request) const;

    ByteArray generate_watchdog_packet_() const;

    Diameter::Packet read_packet_();

    void send_packet_(const ByteArray& send_packet);

    void socket_close_();

    void socket_init_();

    std::vector<unsigned char>
    read_bytes_(unsigned long size);

    static void fill_addr_(struct sockaddr_in& res, const Endpoint& endpoint);

    static ByteArray uint32_to_buf_(uint32_t val);

    std::pair<std::optional<uint32_t>, Diameter::Packet>
    send_and_read_response_(const ByteArray& send_packet);

  private:
    dpi::LoggerPtr logger_;
    const int RETRY_COUNT_ = 2;
    const bool keep_open_connection_;
    const std::string product_name_;
    std::vector<uint32_t> source_addresses_;
    const uint32_t origin_state_id_;
    std::vector<Endpoint> local_endpoints_;
    std::vector<Endpoint> connect_endpoints_;

    std::string origin_host_;
    std::string origin_realm_;
    std::optional<std::string> destination_host_;
    std::optional<std::string> destination_realm_;
    std::string session_id_;
    unsigned int application_id_;
    //unsigned int service_id_;
    mutable unsigned long request_i_;

    int socket_fd_;

    std::mutex send_lock_;
  };

  using DiameterSessionPtr = std::shared_ptr<DiameterSession>;
};

namespace dpi
{
  inline std::string
  DiameterSession::Request::to_string() const
  {
    std::string res;
    res += "{";
    res += "msisdn = " + msisdn;
    res += ", imsi = " + imsi;
    res += ", framed_ip_address = " + ipv4_address_to_string(framed_ip_address);
    res += ", nas_ip_address = " + ipv4_address_to_string(nas_ip_address);
    res += ", rat_type = " + std::to_string(rat_type);
    res += ", timezone = " + std::to_string((unsigned int)timezone);
    res += ", mcc_mnc = " + mcc_mnc;
    res += ", sgsn_ip_address = " + ipv4_address_to_string(sgsn_ip_address);
    res += ", access_network_charging_ip_address = " + ipv4_address_to_string(access_network_charging_ip_address);
    res += ", charging_id = " + std::to_string(charging_id);
    res += "}";

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

