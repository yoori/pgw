#pragma once

#include <vector>

#include <gears/Exception.hpp>

namespace dpi
{
  class IpList
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    static IpList
    load(std::string_view file_path);

    const std::vector<uint32_t>& ips() const;

  private:
    std::vector<uint32_t> ips_;
  };
}

namespace dpi
{
  inline const std::vector<uint32_t>&
  IpList::ips() const
  {
    return ips_;
  }
}
