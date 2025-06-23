#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <optional>

#include <jsoncons/json.hpp>

#include <gears/Exception.hpp>

namespace dpi
{
  class DiameterDictionary
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    enum AVPValueType
    {
      AVP_TYPE_OCTETSTRING = 0,
      AVP_TYPE_INTEGER32,
      AVP_TYPE_INTEGER64,
      AVP_TYPE_UNSIGNED32,
      AVP_TYPE_UNSIGNED64,
      AVP_TYPE_FLOAT32,
      AVP_TYPE_FLOAT64,

      AVP_TYPE_GROUPED,

      AVP_TYPE_UNDEFINED
    };

    struct AVP
    {
      unsigned long avp_code;
      unsigned long vendor_id;
      std::string name;
      AVPValueType base_type;
      std::string custom_type;
      uint8_t flags;
      int min;
      int max;

      std::unordered_map<std::string, std::shared_ptr<const AVP>> child_avps;
    };

    using ConstAVPPtr = std::shared_ptr<const AVP>;

    struct RequestCommand
    {
      unsigned long command_code;
      std::unordered_map<std::string, std::shared_ptr<const AVP>> child_avps;
    };

    using ConstRequestCommandPtr = std::shared_ptr<const RequestCommand>;

    struct AVPPath
    {
      std::vector<ConstAVPPtr> avps;

      std::string to_string() const;
    };

    DiameterDictionary();

    DiameterDictionary(std::string_view file_path);

    std::optional<AVPPath> get_request_avp_path(
      unsigned long request_code,
      std::string_view avp_path)
      const;

  private:
    ConstRequestCommandPtr
    parse_request_(const jsoncons::json& request_json);

    static ConstAVPPtr
    parse_avp_(const jsoncons::json& avp_json);

    static AVPValueType
    str_to_avp_value_type_(const std::string& avp_type_name);

  private:
    std::unordered_map<unsigned long, ConstRequestCommandPtr> requests_;
  };
}
