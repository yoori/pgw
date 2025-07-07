#pragma once

#include <memory>

#include "Value.hpp"

namespace dpi
{
  struct DiameterFieldAdapter
  {
    virtual Value adapt(const Value& value) const = 0;
  };

  using DiameterFieldAdapterPtr = std::shared_ptr<DiameterFieldAdapter>;

  class DiameterFieldAdapterDictionary
  {
  public:
    DiameterFieldAdapterDictionary();

    DiameterFieldAdapterPtr get_adapter(const std::string& name);

    static DiameterFieldAdapterDictionary&
    instance();

  private:
    DiameterFieldAdapterPtr default_adapter_;
    std::unordered_map<std::string, DiameterFieldAdapterPtr> adapters_;
  };
}
