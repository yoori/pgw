#include <arpa/inet.h>

#include <fstream>
#include <sstream>

#include <gears/Tokenizer.hpp>
#include <gears/AsciiStringManip.hpp>

#include "NetworkUtils.hpp"

#include "IpList.hpp"

namespace dpi
{
  IpList IpList::load(std::string_view file_path)
  {
    IpList res;

    std::ifstream file(std::string(file_path).c_str());
    if (!file.is_open())
    {
      std::ostringstream ostr;
      ostr << "Can't open ip list by path: " << file_path;
      throw Exception(ostr.str());
    }

    std::string line;
    while (std::getline(file, line))
    {
      if (!line.empty())
      {
        Gears::StringManip::Splitter<Gears::Ascii::SepSpace, false> splitter(line);
        Gears::SubString token;
        if (splitter.get_token(token) && !token.empty())
        {
          auto ips = string_to_ip_mask(token.str()).expand();
          for (const auto& ip : ips)
          {
            res.ips_.emplace_back(::htonl(ip));
          }
        }
      }
    }

    return res;
  }
}
