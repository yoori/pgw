#include <functional>
#include <iostream>

#include "packet_codes.h"
#include "packet_reader.h"

#include <dpi/NetworkUtils.hpp>

#include "RadiusServer.hpp"

using boost::system::error_code;

namespace dpi
{
  RadiusServer::RadiusServer(
    boost::asio::io_service& io_service,
    const std::string& secret,
    uint16_t port,
    const std::string& filePath)
    : m_radius(io_service, secret, port),
      m_dictionaries(filePath),
      secret_(secret)
  {
    m_dictionaries.resolve(); // TODO: make this in Dictionaries c-tor, but use other class for included dictionaries
    std::cout << "To start receive" << std::endl;
    startReceive();
  }

  void RadiusServer::startReceive()
  {
    m_radius.asyncReceive(
      [this](const auto& error, const auto& packet, const boost::asio::ip::udp::endpoint& source)
      {
        handleReceive(error, packet, source);
      }
    );
  }

  std::string
  print_uint_attr(
    RadProto::PacketReader& packet_reader,
    const std::string& attr_name,
    const std::string& vendor_name = std::string())
  {
    auto attr = packet_reader.get_attribute_by_name(attr_name, vendor_name);
    if (!attr)
    {
      return attr_name + ": no attribute in dictionary";
    }

    auto attr_s = attr->as_uint();
    return attr_name + ": " + (attr_s.has_value() ? std::to_string(*attr_s) : "none");
  }

  std::string byteToHex(uint8_t byte)
  {
    static const std::string digits = "0123456789ABCDEF";
    return {digits[byte / 16], digits[byte % 16]};
  }

  std::string
  print_ipv4_attr(
    RadProto::PacketReader& packet_reader,
    const std::string& attr_name,
    const std::string& vendor_name = std::string())
  {
    auto attr = packet_reader.get_attribute_by_name(attr_name, vendor_name);
    if (!attr)
    {
      return attr_name + ": no attribute in dictionary";
    }

    auto attr_s = attr->as_uint();
    return attr_name + ": " + (attr_s.has_value() ?
      ipv4_address_to_string(*attr_s) + "(" + std::to_string(*attr_s) + ")" :
      "none");
  }

  std::string
  print_string_attr(
    RadProto::PacketReader& packet_reader,
    const std::string& attr_name,
    const std::string& vendor_name = std::string())
  {
    auto attr = packet_reader.get_attribute_by_name(attr_name, vendor_name);
    if (!attr)
    {
      return attr_name + ": no attribute in dictionary";
    }

    auto attr_s = attr->as_string();
    return attr_name + ": " + (attr_s.has_value() ? *attr_s : "none");
  }

  std::string
  print_octets_attr(
    RadProto::PacketReader& packet_reader,
    const std::string& attr_name,
    const std::string& vendor_name = std::string())
  {
    auto attr = packet_reader.get_attribute_by_name(attr_name, vendor_name);
    if (!attr)
    {
      return attr_name + ": no attribute in dictionary";
    }

    auto attr_s = attr->as_octets();
    std::string res = attr_name + ":";

    for (const auto& b : attr_s)
    {
      res += " " + byteToHex(b);
    }

    return res;
  }

  void RadiusServer::handleSend(const error_code& ec)
  {
    if (ec)
    {
      std::cout << "Error asyncSend: " << ec.message() << "\n";
    }

    startReceive();
  }

  void RadiusServer::handleReceive(
    const error_code& error,
    const std::optional<RadProto::Packet>& packet,
    const boost::asio::ip::udp::endpoint& source)
  {
    if (error)
    {
        std::cout << "Error asyncReceive: " << error.message() << "\n";
        return;
    }

    if (packet == std::nullopt)
    {
        std::cout << "Error asyncReceive: the request packet is missing\n";
        return;
    }
    else
    {
      auto send_packet = process_packet_(*packet);
      if (send_packet.has_value())
      {
        m_radius.asyncSend(
          *send_packet,
          source,
          [this](const auto& ec){
            handleSend(ec);
          }
        );
      }
    }
  }
}
