#pragma once

#include <cstdint>

#include <jsoncons/json.hpp>

namespace dpi
{
  struct OctetStats
  {
    OctetStats() {}

    OctetStats(
      uint64_t total_octets_val,
      uint64_t output_octets_val,
      uint64_t input_octets_val)
      : total_octets(total_octets_val),
        output_octets(output_octets_val),
        input_octets(input_octets_val)
    {}

    OctetStats&
    operator+=(const OctetStats& right);

    jsoncons::json to_json() const;

    uint64_t total_octets = 0;
    uint64_t output_octets = 0;
    uint64_t input_octets = 0;
  };
}

namespace dpi
{
  inline OctetStats&
  OctetStats::operator+=(const OctetStats& right)
  {
    total_octets += right.total_octets;
    output_octets += right.output_octets;
    input_octets += right.input_octets;
    return *this;
  }
}
