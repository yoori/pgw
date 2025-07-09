#pragma once

#include <string>

namespace dpi
{
  struct DiameterPassAttribute
  {
    DiameterPassAttribute() {}

    DiameterPassAttribute(
      const std::string& avp_path_val,
      const std::string& property_name_val,
      const std::string& adapter_val = std::string())
      : avp_path(avp_path_val),
        property_name(property_name_val),
        adapter(adapter_val)
    {}

    std::string avp_path;
    std::string property_name;
    std::string adapter;
  };
}
