#pragma once

#include <string>
#include <cstdint>
#include <vector>

#include <gears/Exception.hpp>

namespace dpi
{
  DECLARE_EXCEPTION(InvalidParameter, Gears::DescriptiveException);

  struct IpMask
  {
    // by default match any ip address
    IpMask() {};
    IpMask(uint32_t ip_mask_val, unsigned int fixed_bits_val)
      : ip_mask(ip_mask_val),
        fixed_bits(fixed_bits_val)
    {};

    std::vector<uint32_t> expand() const;

    uint32_t ip_mask = 0;
    unsigned int fixed_bits = 0;
  };

  std::string ipv4_address_to_string(uint32_t ipv4);

  std::string reversed_ipv4_address_to_string(uint32_t ipv4);

  uint32_t string_to_ipv4_address(std::string_view ipv4_str);

  uint32_t string_to_reversed_ipv4_address(std::string_view ipv4_str);

  std::string string_to_hex(const std::vector<uint8_t>& buf);

  IpMask
  string_to_ip_mask(const std::string& string_ip_mask);
}
