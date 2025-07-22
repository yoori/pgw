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

  std::vector<uint32_t> IpMask::expand() const
  {
    std::vector<uint32_t> res;

    uint32_t max_var = 1 << (32 - fixed_bits);
    for (uint32_t ip_var = 0; ip_var < max_var; ++ip_var)
    {
      res.emplace_back(ip_var | (ip_mask & (0xFFFFFFFF << (32 - fixed_bits))));
    }

    return res;
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

  IpMask string_to_ip_mask(const std::string& ip_mask_string)
  {
    IpMask ip_mask;

    std::size_t slash_pos;
    std::size_t asterisk_pos;

    if (ip_mask_string == "*")
    {
      ip_mask.fixed_bits = 0;
      ip_mask.ip_mask = 0;
    }
    else if ((slash_pos = ip_mask_string.find('/')) != std::string::npos)
    {
      ip_mask.fixed_bits = std::atoi(ip_mask_string.substr(slash_pos + 1).c_str());
      ip_mask.ip_mask = string_to_ipv4_address(ip_mask_string.substr(0, slash_pos));
      ip_mask.ip_mask = ip_mask.ip_mask & (0xFFFFFFFF << (32 - ip_mask.fixed_bits));
    }
    else if (ip_mask_string.ends_with(".*"))
    {
      auto f_part = ip_mask_string.substr(0, ip_mask_string.size() - 2);
      Gears::StringManip::Splitter<DomainSeparators, true> splitter(f_part);
      Gears::SubString token;
      uint32_t result_ip = 0;
      unsigned int filled_parts = 0;
      for (int i = 0; i < 4; ++i)
      {
        unsigned char ip_part = 0;
        if (splitter.get_token(token))
        {
          if (!Gears::StringManip::str_to_int(token, ip_part))
          {
            throw InvalidParameter("");
          }

          ++filled_parts;
        }

        result_ip = (result_ip << 8) | ip_part;
      }

      ip_mask.fixed_bits = filled_parts * 8;
      ip_mask.ip_mask = result_ip;
    }
    else
    {
      // try parse as simple ip address
      ip_mask.fixed_bits = 32;
      ip_mask.ip_mask = string_to_ipv4_address(ip_mask_string);
    }

    return ip_mask;
  }
}
