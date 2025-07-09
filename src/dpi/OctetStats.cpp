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

  
}
