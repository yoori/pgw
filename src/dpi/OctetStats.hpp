#pragma once

#include <cstdint>

#include <jsoncons/json.hpp>

namespace dpi
{
  struct OctetStats
  {
    OctetStats() {}

    OctetStats(
      int64_t total_octets_val,
      int64_t output_octets_val,
      int64_t input_octets_val)
      : total_octets(total_octets_val),
        output_octets(output_octets_val),
        input_octets(input_octets_val)
    {}

    bool
    is_null() const;

    void
    set_null();

    OctetStats&
    operator+=(const OctetStats& right);

    OctetStats&
    invert();

    jsoncons::json to_json() const;

    std::string to_string() const;

    int64_t total_octets = 0;
    int64_t output_octets = 0;
    int64_t input_octets = 0;
  };
}

namespace dpi
{
  // OctetStats inlines
  inline bool
  OctetStats::is_null() const
  {
    return total_octets == 0 && output_octets == 0 && input_octets == 0;
  }

  inline void
  OctetStats::set_null()
  {
    total_octets = 0;
    output_octets = 0;
    input_octets = 0;
  }

  inline OctetStats&
  OctetStats::operator+=(const OctetStats& right)
  {
    total_octets += right.total_octets;
    output_octets += right.output_octets;
    input_octets += right.input_octets;
    return *this;
  }

  inline OctetStats&
  OctetStats::invert()
  {
    total_octets = -total_octets;
    output_octets = -output_octets;
    input_octets = -input_octets;
    return *this;
  }
}
