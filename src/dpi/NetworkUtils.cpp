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

  std::string ipv4_address_to_string(uint32_t ipv4)
  {
    /*
    return std::to_string(ipv4 & 0xFF) + "." +
      std::to_string((ipv4 >> 8) & 0xFF) + "." +
      std::to_string((ipv4 >> 16) & 0xFF) + "." +
      std::to_string((ipv4 >> 24) & 0xFF)
      ;
    */
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
