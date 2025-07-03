#pragma once

#include <iostream>
#include <gears/ActiveObjectCallback.hpp>

namespace dpi
{
  class CerrCallback: public Gears::ActiveObjectCallback
  {
  public:
    virtual void
    report_error(
      Severity,
      const Gears::SubString& description,
      const char* = 0)
      noexcept
    {
      std::cerr << description.str() << std::endl;
    }

    virtual
    ~CerrCallback() noexcept
    {}
  };
}
