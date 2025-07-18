#include "OctetStats.hpp"

namespace dpi
{
  jsoncons::json
  OctetStats::to_json() const
  {
    jsoncons::json res;
    res["total_octets"] = total_octets;
    res["output_octets"] = output_octets;
    res["input_octets"] = input_octets;
    return res;
  }

  std::string
  OctetStats::to_string() const
  {
    return std::string("{ ") +
      "total_octets = " + std::to_string(total_octets) +
      ", output_octets = " + std::to_string(output_octets) +
      ", input_octets = " + std::to_string(input_octets) +
      "}";
  }
}
