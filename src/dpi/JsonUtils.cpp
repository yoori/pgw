#include "NetworkUtils.hpp"

#include "JsonUtils.hpp"

namespace dpi
{
  namespace
  {
    class ToJsonVisitor
    {
    public:
      ToJsonVisitor(jsoncons::json& json)
        : json_(json)
      {}

      void
      operator()(const std::string& val)
      {
        json_ = val;
      }

      void
      operator()(int64_t val)
      {
        json_ = val;
      }

      void
      operator()(uint64_t val)
      {
        json_ = val;
      }

      void
      operator()(const ByteArrayValue& val)
      {
        json_ = string_to_hex(val);
      }

    private:
      jsoncons::json& json_;
    };
  }

  std::string
  json_to_string(const jsoncons::json& json)
  {
    jsoncons::json_options json_print_options;
    json_print_options.escape_all_non_ascii(false);
    std::string res;
    jsoncons::encode_json(json, res, json_print_options, jsoncons::indenting::no_indent);
    return res;
  }

  jsoncons::json
  value_to_json(const Value& value)
  {
    jsoncons::json res_json;
    ToJsonVisitor visitor(res_json);
    std::visit(visitor, value);
    return res_json;
  }
}
