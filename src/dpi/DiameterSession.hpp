#pragma once

#include <string>
#include <optional>

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
      //unsigned long service_id = 0;
      uint32_t framed_ip_address = 0;
      uint32_t nas_ip_address = 0;
      uint32_t rat_type = 0;
      unsigned char timezone = 0; //< RADIUS: Vendor-Specific.3GPP.MS-TimeZone.TZ
      uint32_t mcc = 0;
      uint32_t mnc = 0;
      uint32_t sgsn_ip_address = 0; //< RADIUS: Vendor-Specific.3GPP.SGSN-Address
      uint32_t access_network_charging_ip_address = 0;
      //< RADIUS: Vendor-Specific.3GPP.Access-Network-Charging-Address
      uint32_t charging_id = 0; //< RADIUS: Vendor-Specific.3GPP.Charging-ID

      std::string to_string() const;
    };

    DiameterSession(
      dpi::LoggerPtr logger,
      std::vector<Endpoint> local_endpoints,
      std::vector<Endpoint> connect_endpoints,
      std::string origin_host,
      std::string origin_realm,
      std::optional<std::string> destination_host,
      bool keep_open_connection = false
      );

    virtual ~DiameterSession();

    void set_logger(dpi::LoggerPtr logger);

    void open();

    unsigned int send_cc_init(const Request& request);

  private:
    ByteArray generate_exchange_packet_() const;

    ByteArray generate_cc_init_(const Request& request) const;

    ByteArray generate_cc_update_(const Request& request) const;

    ByteArray generate_cc_terminate_(const Request& request) const;

    Diameter::Packet generate_base_cc_packet_(const Request& request)
      const;

    Diameter::Packet read_packet_();

    void send_packet_(const ByteArray& send_packet);

    void socket_close_();

    void socket_init_();

    std::vector<unsigned char>
    read_bytes_(unsigned long size);

    static void fill_addr_(struct sockaddr_in& res, const Endpoint& endpoint);

    static ByteArray uint32_to_buf_(uint32_t val);

  private:
    dpi::LoggerPtr logger_;
    const int RETRY_COUNT_ = 2;
    const bool keep_open_connection_;
    std::vector<Endpoint> local_endpoints_;
    std::vector<Endpoint> connect_endpoints_;

    std::string origin_host_;
    std::string origin_realm_;
    std::optional<std::string> destination_host_;
    std::string session_id_;
    unsigned int application_id_;
    //unsigned int service_id_;
    mutable unsigned long request_i_;

    int socket_fd_;
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
    res += ", mcc = " + std::to_string(mcc);
    res += ", mnc = " + std::to_string(mnc);
    res += ", sgsn_ip_address = " + ipv4_address_to_string(sgsn_ip_address);
    res += ", access_network_charging_ip_address = " + ipv4_address_to_string(access_network_charging_ip_address);
    res += ", charging_id = " + std::to_string(charging_id);
    res += "}";

    return res;
  }
}

