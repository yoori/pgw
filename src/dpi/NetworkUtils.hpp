#pragma once

#include <string>
#include <cstdint>
#include <vector>

#include <gears/Exception.hpp>

namespace dpi
{
  DECLARE_EXCEPTION(InvalidParameter, Gears::DescriptiveException);

  std::string ipv4_address_to_string(uint32_t ipv4);

  std::string reversed_ipv4_address_to_string(uint32_t ipv4);

  uint32_t string_to_ipv4_address(std::string_view ipv4_str);

  uint32_t string_to_reversed_ipv4_address(std::string_view ipv4_str);

  std::string string_to_hex(const std::vector<uint8_t>& buf);
}
