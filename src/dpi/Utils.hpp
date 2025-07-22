#pragma once

#include <string>
#include <vector>

namespace dpi
{
  // convert value by Binary-Coded Decimal (BCD)
  std::vector<uint8_t>
  bcd_encode(const std::string& val);
}
