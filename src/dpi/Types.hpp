#pragma once

#include <cstdint>

namespace dpi
{
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
}
