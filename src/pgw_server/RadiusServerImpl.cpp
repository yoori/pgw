#include <packet_reader.h>
#include <packet_codes.h>

#include "RadiusServerImpl.hpp"

namespace dpi
{
  RadiusServerImpl::RadiusServerImpl(
    boost::asio::io_service& io_service,
    const std::string& secret,
    uint16_t port,
    const std::string& dictionary_file_path,
    dpi::ProcessorPtr processor)
    : RadiusServer(io_service, secret, port, dictionary_file_path),
      processor_(std::move(processor))
  {}

  std::optional<RadProto::Packet>
  RadiusServerImpl::process_packet_(const RadProto::Packet& request)
  {
    std::cout << "RADIUS INPUT PACKET" << std::endl;

    // Check request.type() == RadProto::ACCESS_REQUEST
    RadProto::PacketReader packet_reader(request, m_dictionaries, secret_);
    auto acct_status_type_attr = packet_reader.get_attribute_by_name("Acct-Status-Type");
    auto calling_station_id_attr = packet_reader.get_attribute_by_name("Calling-Station-Id");
    auto called_station_id_attr = packet_reader.get_attribute_by_name("Called-Station-Id");
    auto framed_ip_address_attr = packet_reader.get_attribute_by_name("Framed-IP-Address");
    auto nas_ip_address_attr = packet_reader.get_attribute_by_name("NAS-IP-Address");
    auto imsi_attr = packet_reader.get_attribute_by_name("IMSI", "3GPP");
    auto imei_attr = packet_reader.get_attribute_by_name("IMEISV", "3GPP");
    auto rat_type_attr = packet_reader.get_attribute_by_name("RAT-Type", "3GPP");
    auto mcc_mnc_attr = packet_reader.get_attribute_by_name("SGSN-MCC-MNC", "3GPP");
    unsigned int tz = 0;
    // MS-TimeZone struct => TZ (2 bytes)
    {
      auto attr = packet_reader.get_attribute_by_name("MS-TimeZone", "3GPP");
      if (attr)
      {
        auto attr_s = attr->as_octets();
        if (attr_s.size() > 0)
        {
          tz = static_cast<unsigned int>(attr_s[0]);
        }
      }
    }
    auto sgsn_address_attr = packet_reader.get_attribute_by_name("SGSN-Address", "3GPP");
    auto cg_address_attr = packet_reader.get_attribute_by_name("CG-Address", "3GPP");
    auto charging_id_attr = packet_reader.get_attribute_by_name("Charging-ID", "3GPP");
    auto charging_characteristics_attr = packet_reader.get_attribute_by_name("Charging-Characteristics", "3GPP");
    auto gprs_negotiated_qos_profile_attr = packet_reader.get_attribute_by_name(
      "GPRS-Negotiated-QoS-profile", "3GPP");
    auto nsapi_attr = packet_reader.get_attribute_by_name("NSAPI", "3GPP");
    auto selection_mode_attr = packet_reader.get_attribute_by_name("Selection-Mode", "3GPP");
    auto user_location_info_attr = packet_reader.get_attribute_by_name("User-Location-Info", "3GPP");

    /*
    std::cout << print_octets_attr(packet_reader, "User-Location-Info", "3GPP") << std::endl;
    */

    bool res = processor_->process_request(
      static_cast<dpi::Manager::AcctStatusType>(*(acct_status_type_attr->as_uint())),
      calling_station_id_attr ? *(calling_station_id_attr->as_string()) : std::string(),
      called_station_id_attr ? *(called_station_id_attr->as_string()) : std::string(),
      imsi_attr ? *(imsi_attr->as_string()) : std::string(), // imsi
      imei_attr ? *(imei_attr->as_string()) : std::string(), // imei
      framed_ip_address_attr ? *(framed_ip_address_attr->as_uint()) : 0, // framed_ip_address
      nas_ip_address_attr ? *(nas_ip_address_attr->as_uint()) : 0, // nas_ip_address
      rat_type_attr ? *(rat_type_attr->as_uint()) : 0, // rat_type
      mcc_mnc_attr ? *(mcc_mnc_attr->as_string()) : std::string(), // mcc_mnc
      tz, // tz
      sgsn_address_attr ? *(sgsn_address_attr->as_uint()) : 0, // sgsn_ip_address
      cg_address_attr ? *(cg_address_attr->as_uint()) : 0, // access_network_charging_ip_address
      charging_id_attr ? *(charging_id_attr->as_uint()) : 0, // charging_id
      (gprs_negotiated_qos_profile_attr ?
        *(gprs_negotiated_qos_profile_attr->as_string()) : std::string()).c_str(), // gprs_negotiated_qos_profile
      user_location_info_attr ?
        user_location_info_attr->as_octets() : RadProto::ByteArray(), // user_location_info
      nsapi_attr ? *(nsapi_attr->as_string()) : std::string(), // nsapi
      selection_mode_attr ? *(selection_mode_attr->as_string()) : std::string(), // selection_mode
      charging_characteristics_attr ?
        *(charging_characteristics_attr->as_string()) : std::string() // charging_characteristics
    );

    if (res)
    {
      return RadProto::Packet(
        RadProto::ACCESS_ACCEPT,
        request.id(),
        request.auth(),
        std::vector<RadProto::Attribute*>(),
        std::vector<RadProto::VendorSpecific>());
    }

    return std::nullopt;
  }
}
