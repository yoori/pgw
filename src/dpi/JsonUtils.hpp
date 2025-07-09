#pragma once

#include <string>
#include <jsoncons/json.hpp>

#include "Value.hpp"

namespace dpi
{
  std::string
  json_to_string(const jsoncons::json& json);

  jsoncons::json
  value_to_json(const Value& value);
}
