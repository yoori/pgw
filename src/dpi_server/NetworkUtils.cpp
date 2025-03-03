#include "NetworkUtils.hpp"

namespace dpi
{
  std::string ipv4_address_to_string(uint32_t ipv4)
  {
    return std::to_string(ipv4 & 0xFF) + "." +
      std::to_string((ipv4 >> 8) & 0xFF) + "." +
      std::to_string((ipv4 >> 16) & 0xFF) + "." +
      std::to_string((ipv4 >> 24) & 0xFF)
      ;
  }
}
