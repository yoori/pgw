#pragma once

#include <string>

#include <Diameter/Packet.hpp>


class DiameterSession
{
public:
  DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
  DECLARE_EXCEPTION(NetworkError, Exception);
  DECLARE_EXCEPTION(ConnectionClosedOnRead, NetworkError);
  DECLARE_EXCEPTION(DiameterError, Exception);

  DiameterSession(
    std::string connect_host,
    int connect_port,
    std::string origin_host,
    std::string origin_realm);

  virtual ~DiameterSession();

  bool send_cc_init(
    const std::string& msisdn,
    unsigned long service_id);

private:
  ByteArray generate_exchange_packet_() const;

  ByteArray generate_cc_init_(
    const std::string& msisdn,
    unsigned long service_id) const;

  ByteArray generate_cc_update_(
    const std::string& msisdn,
    unsigned long service_id) const;

  ByteArray generate_cc_terminate_(
    const std::string& msisdn,
    unsigned long service_id) const;

  Diameter::Packet generate_base_cc_packet_(
    const std::string& msisdn,
    unsigned long service_id)
    const;

  Diameter::Packet read_packet_();

  void send_packet_(const ByteArray& send_packet);

  void socket_close_();

  void socket_init_();

  std::vector<unsigned char>
  read_bytes_(unsigned long size) const;

private:
  const int RETRY_COUNT_ = 2;
  std::string connect_host_;
  int connect_port_;

  std::string origin_host_;
  std::string origin_realm_;
  std::string session_id_;
  unsigned int application_id_;
  //unsigned int service_id_;
  mutable unsigned long request_i_;

  int socket_fd_;
};
