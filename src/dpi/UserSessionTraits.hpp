#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <memory>

#include "NetworkUtils.hpp"
#include "UserSessionPropertyContainer.hpp"

namespace dpi
{
  // Session linked to user
  struct UserSessionTraits
  {
    uint32_t framed_ip_address = 0;

    std::string msisdn;
    std::string imei;
    std::string imsi;
    std::string called_station_id;
    uint32_t nas_ip_address = 0;
    uint32_t rat_type = 0;
    unsigned char timezone = 0; //< RADIUS: Vendor-Specific.3GPP.MS-TimeZone.TZ
    std::string mcc_mnc;
    uint32_t sgsn_ip_address = 0; //< RADIUS: Vendor-Specific.3GPP.SGSN-Address
    uint32_t access_network_charging_ip_address = 0;
    //< RADIUS: Vendor-Specific.3GPP.Access-Network-Charging-Address
    uint32_t charging_id = 0; //< RADIUS: Vendor-Specific.3GPP.Charging-ID
    std::string gprs_negotiated_qos_profile; //< RADIUS
    std::vector<uint8_t> user_location_info;
    std::string nsapi;
    std::string selection_mode;
    std::string charging_characteristics;

    UserSessionPropertyContainerPtr user_session_property_container;

    bool
    operator==(const UserSessionTraits& right) const;

    std::string to_string() const;
  };

  using ConstUserSessionTraitsPtr = std::shared_ptr<const UserSessionTraits>;
}

namespace dpi
{
  inline bool
  UserSessionTraits::operator==(const UserSessionTraits& right) const
  {
    return framed_ip_address == right.framed_ip_address &&
      msisdn == right.msisdn &&
      imei == right.imei &&
      imsi == right.imsi &&
      called_station_id == right.called_station_id &&
      nas_ip_address == right.nas_ip_address &&
      rat_type == right.rat_type &&
      timezone == right.timezone &&
      mcc_mnc == right.mcc_mnc &&
      sgsn_ip_address == right.sgsn_ip_address &&
      access_network_charging_ip_address == right.access_network_charging_ip_address &&
      charging_id == right.charging_id &&
      gprs_negotiated_qos_profile == right.gprs_negotiated_qos_profile &&
      user_location_info.size() == right.user_location_info.size() &&
      std::equal(user_location_info.begin(), user_location_info.end(), right.user_location_info.begin()) &&
      nsapi == right.nsapi &&
      selection_mode == right.selection_mode &&
      charging_characteristics == right.charging_characteristics;
  }

  inline std::string
  UserSessionTraits::to_string() const
  {
    return std::string("{") +
      "\"framed_ip_address\": \"" + ipv4_address_to_string(framed_ip_address) + "\"," +
      "\"msisdn\": \"" + msisdn + "\"," +
      "\"imsi\": \"" + imsi + "\"," +
      "\"called_station_id\": \"" + called_station_id + "\"," +
      "\"nas_ip_address\": \"" + ipv4_address_to_string(nas_ip_address) + "\"," +
      "\"rat_type\": " + std::to_string(rat_type) + "," +
      "\"timezone\": " + std::to_string(timezone) + "," +
      "\"mcc_mnc\": \"" + mcc_mnc + "\"," +
      "\"sgsn_ip_address\": \"" + ipv4_address_to_string(sgsn_ip_address) + "\"," +
      "\"access_network_charging_ip_address\": \"" + ipv4_address_to_string(access_network_charging_ip_address) + "\"," +
      "\"charging_id\": \"" + std::to_string(charging_id) + "\"," +
      "\"gprs_negotiated_qos_profile\": \"" + gprs_negotiated_qos_profile + "\"," +
      "\"user_location_info\": \"" + string_to_hex(user_location_info) + "\"," +
      "\"nsapi\": \"" + nsapi + "\","
      "\"selection_mode\": \"" + selection_mode + "\","
      "\"charging_characteristics\": \"" + charging_characteristics + "\""
      "}";
  }
}
