#include <functional>
#include <iostream>

#include "packet_codes.h"
#include "packet_reader.h"

#include <dpi/NetworkUtils.hpp>

#include "RadiusServer.hpp"

using boost::system::error_code;

namespace dpi
{
  namespace
  {
    std::string
    get_radius_string_attribute(
      const RadProto::PacketReader& packet_reader,
      const std::string& attribute_name,
      const std::string& vendor_name = std::string())
    {
      if (vendor_name.empty())
      {
        auto attr = packet_reader.get_attribute_by_name(attribute_name);
        if (attr)
        {
          return *attr->as_string();
        }
      }
      else
      {
        auto attr = packet_reader.get_attribute_by_name(attribute_name, vendor_name);
        if (attr)
        {
          return *attr->as_string();
        }
      }

      return std::string();
    }

    int
    get_radius_uint_attribute(
      const RadProto::PacketReader& packet_reader,
      const std::string& attribute_name,
      const std::string& vendor_name = std::string())
    {
      if (vendor_name.empty())
      {
        auto attr = packet_reader.get_attribute_by_name(attribute_name);
        if (attr)
        {
          return *attr->as_uint();
        }
      }
      else
      {
        auto attr = packet_reader.get_attribute_by_name(attribute_name, vendor_name);
        if (attr)
        {
          return *attr->as_uint();
        }
      }

      return 0;
    }

    std::vector<unsigned char>
    get_radius_octets_attribute(
      const RadProto::PacketReader& packet_reader,
      const std::string& attribute_name,
      const std::string& vendor_name = std::string())
    {
      if (vendor_name.empty())
      {
        auto attr = packet_reader.get_attribute_by_name(attribute_name);
        if (attr)
        {
          return attr->as_octets();
        }
      }
      else
      {
        auto attr = packet_reader.get_attribute_by_name(attribute_name, vendor_name);
        if (attr)
        {
          return attr->as_octets();
        }
      }

      return std::vector<unsigned char>();
    }
  };

  RadiusServer::RadiusServer(
    boost::asio::io_service& io_service,
    uint16_t listen_port,
    const std::string& secret,
    const std::string& dictionary_file_path,
    dpi::ProcessorPtr processor,
    RadiusUserSessionPropertyExtractorPtr radius_user_session_property_extractor)
    : radius_(
        io_service,
        secret,
        listen_port,
        [this](const auto& error, const auto& packet, const boost::asio::ip::udp::endpoint& source)
        {
          handle_receive_(error, packet, source);
        }),
      dictionaries_(dictionary_file_path),
      secret_(secret),
      processor_(std::move(processor)),
      radius_user_session_property_extractor_(std::move(radius_user_session_property_extractor))
  {
    dictionaries_.resolve(); // TODO: make this in Dictionaries c-tor, but use other class for included dictionaries

    std::cout << "To start receive" << std::endl;
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

  void RadiusServer::handle_send(const error_code& ec)
  {
    if (ec)
    {
      std::cout << "Error asyncSend: " << ec.message() << "\n";
    }
  }

  void RadiusServer::handle_receive_(
    const error_code& error,
    const std::optional<RadProto::Packet>& packet,
    const boost::asio::ip::udp::endpoint& source)
  {
    std::cout << "RadiusServer::handle_receive_" << std::endl;

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
        radius_.asyncSend(
          *send_packet,
          source,
          [this](const auto& ec){
            handle_send(ec);
          }
        );
      }
    }
  }

  std::optional<RadProto::Packet>
  RadiusServer::process_packet_(const RadProto::Packet& request)
  {
    //std::cout << "RADIUS INPUT PACKET" << std::endl;

    // get basic fields required for logic
    RadProto::PacketReader packet_reader(request, dictionaries_, secret_);
    auto acct_status_type_attr = packet_reader.get_attribute_by_name("Acct-Status-Type");
    auto calling_station_id_attr = packet_reader.get_attribute_by_name("Calling-Station-Id");
    auto framed_ip_address_attr = packet_reader.get_attribute_by_name("Framed-IP-Address");
    auto acct_session_id_attr = packet_reader.get_attribute_by_name("Acct-Session-Id");

    uint32_t framed_ip_address = 0;

    if (acct_status_type_attr &&
      framed_ip_address_attr &&
      calling_station_id_attr &&
      (framed_ip_address = *framed_ip_address_attr->as_uint()) != 0)
    {
      UserSessionPropertyContainerPtr user_session_property_container =
        radius_user_session_property_extractor_->extract(request);

      std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] RADIUS: acct_status_type = " << *acct_status_type_attr->as_uint() <<
        ", pass_attributes = " << user_session_property_container->values.size() <<
        ", framed_ip_address = " << dpi::ipv4_address_to_string(framed_ip_address) <<
        ", msisdn = " << *calling_station_id_attr->as_string() <<
        std::endl;

      // Check request.type() == RadProto::ACCOUNTING_REQUEST

      dpi::UserSessionTraits user_session_traits;
      user_session_traits.framed_ip_address = framed_ip_address;
      user_session_traits.msisdn = *calling_station_id_attr->as_string();
      user_session_traits.radius_session_id = acct_session_id_attr ? *acct_session_id_attr->as_string() : std::string();

      /*
      {
        user_session_traits.called_station_id = get_radius_string_attribute(packet_reader, "Called-Station-Id");
        user_session_traits.msisdn = get_radius_string_attribute(packet_reader, "Calling-Station-Id");
        user_session_traits.imsi = get_radius_string_attribute(packet_reader, "IMSI", "3GPP");
        user_session_traits.imei = get_radius_string_attribute(packet_reader, "IMEISV", "3GPP");
        user_session_traits.mcc_mnc = get_radius_string_attribute(packet_reader, "SGSN-MCC-MNC", "3GPP");
        user_session_traits.charging_characteristics = get_radius_string_attribute(
          packet_reader, "Charging-Characteristics", "3GPP");
        user_session_traits.selection_mode = get_radius_string_attribute(
          packet_reader, "Selection-Mode", "3GPP");
        user_session_traits.charging_id = get_radius_uint_attribute(
          packet_reader, "Charging-ID", "3GPP");
        user_session_traits.nsapi = get_radius_string_attribute(
          packet_reader, "NSAPI", "3GPP");
        user_session_traits.gprs_negotiated_qos_profile = get_radius_string_attribute(
          packet_reader, "GPRS-Negotiated-QoS-profile", "3GPP");
        user_session_traits.rat_type = get_radius_uint_attribute(
          packet_reader, "RAT-Type", "3GPP");
        user_session_traits.user_location_info = get_radius_octets_attribute(
          packet_reader, "User-Location-Info", "3GPP");
        user_session_traits.nas_ip_address = get_radius_uint_attribute(
          packet_reader, "NAS-IP-Address");
        user_session_traits.sgsn_ip_address = get_radius_uint_attribute(
          packet_reader, "SGSN-Address", "3GPP");
        user_session_traits.access_network_charging_ip_address = get_radius_uint_attribute(
          packet_reader, "CG-Address", "3GPP");

        unsigned int tz = 0;
        // MS-TimeZone struct => TZ (2 bytes)
        {
          auto attr = packet_reader.get_attribute_by_name("MS-TimeZone", "3GPP");
          if (attr)
          {
            auto attr_s = attr->as_octets();
            if (attr_s.size() > 0)
            {
              user_session_traits.timezone = static_cast<unsigned int>(attr_s[0]);
            }
          }
        }
      }
      */

      user_session_traits.user_session_property_container = user_session_property_container;

      bool res = processor_->process_request(
        static_cast<dpi::Manager::AcctStatusType>(*(acct_status_type_attr->as_uint())),
        calling_station_id_attr ? *(calling_station_id_attr->as_string()) : std::string(),
        framed_ip_address_attr ? *(framed_ip_address_attr->as_uint()) : 0, // framed_ip_address
        user_session_traits
      );

      if (res)
      {
        std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] RADIUS: return 1" << std::endl;
        return RadProto::Packet(
          RadProto::ACCOUNTING_RESPONSE,
          request.id(),
	  request.auth(),
          std::vector<RadProto::Attribute*>(),
          std::vector<RadProto::VendorSpecific>(),
          true);
      }
    }

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] RADIUS: return 0" << std::endl;
    return std::nullopt;
  }

  Value
  RadiusServer::attribute_to_value_(const RadProto::Attribute& attribute)
  {
    Value result;

    auto try_as_int = attribute.as_int();
    if (try_as_int.has_value())
    {
      result.emplace<int64_t>(*try_as_int);
      return result;
    }

    auto try_as_uint = attribute.as_uint();
    if (try_as_uint.has_value())
    {
      result.emplace<uint64_t>(*try_as_uint);
      return result;
    }

    auto try_as_string = attribute.as_string();
    if (try_as_string.has_value())
    {
      result.emplace<std::string>(*try_as_string);
      return result;
    }

    auto octets = attribute.as_octets();
    result.emplace<ByteArrayValue>(octets);
    return result;
  }
}
