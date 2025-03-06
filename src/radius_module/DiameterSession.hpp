#pragma once

#include <string>
#include <optional>

#include <Diameter/Packet.hpp>


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

  DiameterSession(
    std::vector<Endpoint> local_endpoints,
    std::vector<Endpoint> connect_endpoints,
    std::string origin_host,
    std::string origin_realm,
    std::optional<std::string> destination_host,
    bool keep_open_connection = true
    );

  virtual ~DiameterSession();

  void open();

  unsigned int send_cc_init(
    const std::string& msisdn,
    unsigned long service_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address
    );

private:
  ByteArray generate_exchange_packet_() const;

  ByteArray generate_cc_init_(
    const std::string& msisdn,
    unsigned long service_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address
    ) const;

  ByteArray generate_cc_update_(
    const std::string& msisdn,
    unsigned long service_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address
    ) const;

  ByteArray generate_cc_terminate_(
    const std::string& msisdn,
    unsigned long service_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address
    ) const;

  Diameter::Packet generate_base_cc_packet_(
    const std::string& msisdn,
    unsigned long service_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address
    )
    const;

  Diameter::Packet read_packet_();

  void send_packet_(const ByteArray& send_packet);

  void socket_close_();

  void socket_init_();

  std::vector<unsigned char>
  read_bytes_(unsigned long size) const;

  static void fill_addr_(struct sockaddr_in& res, const Endpoint& endpoint);

private:
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
