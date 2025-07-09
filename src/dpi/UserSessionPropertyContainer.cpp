#include "JsonUtils.hpp"
#include "UserSessionPropertyContainer.hpp"

namespace dpi
{
  jsoncons::json
  UserSessionPropertyContainer::to_json() const
  {
    std::vector<jsoncons::json> values_json;
    for (const auto& [property_name, value] : values)
    {
      jsoncons::json value_json;
      value_json["property_name"] = property_name;
      value_json["value"] = value_to_json(value);
      values_json.emplace_back(std::move(value_json));
    }
    jsoncons::json res_json;
    res_json["values"] = values_json;
    return res_json;
  }

  std::string
  UserSessionPropertyContainer::to_string() const
  {
    return json_to_string(to_json());
  }
}
