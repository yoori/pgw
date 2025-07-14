#pragma once

#include <cstdint>
#include <vector>

namespace dpi
{
  enum Direction
  {
    D_NONE = 0,
    D_OUTPUT,
    D_INPUT
  };

  enum class UsageReportingReason: uint32_t
  {
    THRESHOLD = 0, //
    QHT = 1,
    FINAL = 2, //
    QUOTA_EXHAUSTED = 3,
    VALIDITY_TIME = 4, //
    OTHER_QUOTA_TYPE = 5, // send for rg where no limit reached
    RATING_CONDITION_CHANGE = 6,
    FORCED_REAUTHORISATION = 7,
    POOL_EXHAUSTED = 8
  };

  enum class EventTrigger: uint32_t
  {
    RAT_CHANGE = 2, // RAT-Type changed
    USER_LOCATION_CHANGE = 13, // User-Location changed
    // NO_EVENT_TRIGGERS = 14 : only in CCA/RAR
    UE_IP_ADDRESS_ALLOCATE = 18, // Framed-IP-Address changed
    UE_IP_ADDRESS_RELEASE = 19,
    AN_GW_CHANGE = 21, // SGSN-Address (passed as AN-GW-Address) changed
    TAI_CHANGE = 26, // User-Location changed
    ECGI_CHANGE = 27 // User-Location changed
    // USAGE_REPORT = 33 : only in CCA/RAR
  };

  using EventTriggerArray = std::vector<EventTrigger>;
}
