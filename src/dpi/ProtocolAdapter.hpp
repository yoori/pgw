#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace dpi
{
  class ProtocolAdapter
  {
  public:
    ProtocolAdapter();

    const std::string&
    ndpi_protocol_to_string(uint32_t ndpi_protocol) const;

  private:
    const std::string empty_protocol_;
    std::unordered_map<uint32_t, std::string> ndpi_protocols_;
  };
}
