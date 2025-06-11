#pragma once

#include <string>
#include <optional>
#include <cstdint>

namespace dpi
{
  // Session linked to user
  struct UserSessionTraits
  {
    uint32_t framed_ip_address = 0;

    std::string msisdn;
    std::string imsi;
    uint32_t nas_ip_address = 0;
    uint32_t rat_type = 0;
    unsigned char timezone = 0; //< RADIUS: Vendor-Specific.3GPP.MS-TimeZone.TZ
    std::string mcc_mnc;
    uint32_t sgsn_ip_address = 0; //< RADIUS: Vendor-Specific.3GPP.SGSN-Address
    uint32_t access_network_charging_ip_address = 0;
    //< RADIUS: Vendor-Specific.3GPP.Access-Network-Charging-Address
    uint32_t charging_id = 0; //< RADIUS: Vendor-Specific.3GPP.Charging-ID
    std::string gprs_negotiated_qos_profile; //< RADIUS
  };
}
