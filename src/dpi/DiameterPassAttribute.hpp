#pragma once

#include <string>

namespace dpi
{
  struct RadiusAttributeSource
  {
    RadiusAttributeSource() {}

    RadiusAttributeSource(const std::string& name_val, const std::string& vendor_val = std::string())
      : name(name_val),
        vendor(vendor_val)
    {}

    std::string name;
    std::string vendor;
  };

  struct DiameterPassAttribute
  {
    DiameterPassAttribute() {}

    DiameterPassAttribute(const std::string& avp_path_val, const RadiusAttributeSource& source_val)
      : avp_path(avp_path_val),
        source(source_val)
    {}

    std::string avp_path;
    RadiusAttributeSource source;
  };
}
