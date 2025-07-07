#include <arpa/inet.h>
#include <iostream>

#include <gears/StringManip.hpp>

#include "NetworkUtils.hpp"

namespace dpi
{
  namespace
  {
    using DomainSeparators = const Gears::Ascii::Char1Category<'.'>;
  }

  std::string byte_to_hex(uint8_t byte)
  {
    static const char BUF[] = "0123456789ABCDEF";
    const char res[] = {
      BUF[byte / 16],
      BUF[byte % 16]
    };
    return std::string(res, res + 2);
  }

  std::string string_to_hex(const std::vector<uint8_t>& buf)
  {
    std::string res;
    for (uint8_t el : buf)
    {
      res += byte_to_hex(el);
    }
    return res;
  }

  std::string ipv4_address_to_string(uint32_t ipv4)
  {
    return std::to_string(ipv4 & 0xFF) + "." +
      std::to_string((ipv4 >> 8) & 0xFF) + "." +
      std::to_string((ipv4 >> 16) & 0xFF) + "." +
      std::to_string((ipv4 >> 24) & 0xFF)
      ;
  }

  std::string reversed_ipv4_address_to_string(uint32_t ipv4)
  {
    return std::to_string((ipv4 >> 24) & 0xFF) + "." +
      std::to_string((ipv4 >> 16) & 0xFF) + "." +
      std::to_string((ipv4 >> 8) & 0xFF) + "." +
      std::to_string(ipv4 & 0xFF)
      ;
  }

  uint32_t string_to_ipv4_address(std::string_view ipv4_str)
  {
    Gears::StringManip::Splitter<DomainSeparators, true> splitter(ipv4_str);
    Gears::SubString token;
    uint32_t result_ip = 0;
    while (splitter.get_token(token))
    {
      unsigned char ip_part;
      if (!Gears::StringManip::str_to_int(token, ip_part))
      {
        throw InvalidParameter("");
      }

      result_ip = (result_ip << 8) | ip_part;
    }

    return result_ip;
  }

  uint32_t string_to_reversed_ipv4_address(std::string_view ipv4_str)
  {
    return ::htonl(string_to_ipv4_address(ipv4_str));
  }
}
