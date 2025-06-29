#include <fstream>
#include <jsoncons/json.hpp>
#include <gears/Tokenizer.hpp>

#include "DiameterDictionary.hpp"

namespace dpi
{
  std::string
  DiameterDictionary::AVPPath::to_string() const
  {
    std::string res;
    for (auto avp_it = avps.begin(); avp_it != avps.end(); ++avp_it)
    {
      if (avp_it != avps.begin())
      {
        res += ".";
      }

      res += (*avp_it)->name;
    }

    return res;
  }

  DiameterDictionary::DiameterDictionary()
  {}

  DiameterDictionary::DiameterDictionary(std::string_view file_path)
  {
    std::ifstream read_file(std::string(file_path).c_str());
    if (!read_file.is_open())
    {
      throw Exception(std::string("Can't open file: ") + std::string(file_path));
    }

    std::stringstream dict_buf;
    dict_buf << read_file.rdbuf();

    jsoncons::json dict_json = jsoncons::json::parse(dict_buf.str());
    for (const auto& request_json : dict_json["requests"].array_range())
    {
      ConstRequestCommandPtr request_command = parse_request_(request_json);
      requests_.emplace(request_command->command_code, request_command);
    }
  }

  std::optional<DiameterDictionary::AVPPath>
  DiameterDictionary::get_request_avp_path(
    unsigned long request_code,
    std::string_view avp_path)
    const
  {
    auto command_it = requests_.find(request_code);
    if (command_it == requests_.end())
    {
      std::cerr << "P1" << std::endl;
      return std::nullopt;
    }

    AVPPath result_avp_path;

    Gears::StringManip::SplitPeriod splitter{Gears::SubString(avp_path)};
    Gears::SubString token;
    ConstAVPPtr cur_avp;
    while (splitter.get_token(token))
    {
      /*
      std::cerr << "A: " << token.str() << std::endl;
      if (cur_avp)
      {
        std::cerr << ">>>>>>>>>> " << cur_avp->name << std::endl;
        for (const auto& c_avp : cur_avp->child_avps)
        {
          std::cerr << "  " << c_avp.first << std::endl;
        }
        std::cerr << "<<<<<<<<<<" << std::endl;
      }
      */

      if (!cur_avp)
      {
        auto avp_it = command_it->second->child_avps.find(token.str());
        if (avp_it == command_it->second->child_avps.end())
        {
          //std::cerr << "P2" << std::endl;
          return std::nullopt;
        }

        cur_avp = avp_it->second;
      }
      else
      {
        auto avp_it = cur_avp->child_avps.find(token.str());
        if (avp_it == cur_avp->child_avps.end())
        {
          //std::cerr << "P3: " << token.str() << std::endl;
          return std::nullopt;
        }

        cur_avp = avp_it->second;
      }

      result_avp_path.avps.emplace_back(cur_avp);
    }

    return result_avp_path;
  }

  DiameterDictionary::ConstRequestCommandPtr
  DiameterDictionary::parse_request_(const jsoncons::json& request_json)
  {
    std::shared_ptr<RequestCommand> result_request =
      std::make_shared<RequestCommand>();
    result_request->command_code = request_json["code"].as_integer<uint32_t>();
    std::vector<ConstAVPPtr> child_avps;
    for (const auto& child_avp : request_json["childs"].array_range())
    {
      ConstAVPPtr avp = parse_avp_(child_avp);
      result_request->child_avps.emplace(avp->name, avp);
    }

    return result_request;
  }

  DiameterDictionary::ConstAVPPtr
  DiameterDictionary::parse_avp_(const jsoncons::json& avp_json)
  {
    std::shared_ptr<AVP> result_avp = std::make_shared<AVP>();
    result_avp->avp_code = avp_json["code"].as_integer<uint32_t>();
    result_avp->flags = avp_json.contains("flags") ?
      avp_json["flags"].as_integer<uint32_t>() : 0;
    result_avp->vendor_id = avp_json.contains("vendor_id") ?
      avp_json["vendor_id"].as_integer<uint32_t>() : 0;
    result_avp->name = avp_json.contains("name") ?
      avp_json["name"].as_string() : std::string();
    result_avp->base_type = avp_json.contains("base_type") ?
      str_to_avp_value_type_(avp_json["base_type"].as_string()) :
      AVP_TYPE_UNDEFINED;
    result_avp->custom_type = avp_json.contains("custom_type") ?
      avp_json["custom_type"].as_string() : std::string();
    result_avp->min = avp_json.contains("min") ?
      avp_json["min"].as_integer<uint32_t>() : 0;
    result_avp->max = avp_json.contains("max") ?
      avp_json["max"].as_integer<int32_t>() : 1;
    if (avp_json.contains("childs"))
    {
      for (const auto& child_avp_json : avp_json["childs"].array_range())
      {
        ConstAVPPtr child_avp = parse_avp_(child_avp_json);
        result_avp->child_avps.emplace(child_avp->name, child_avp);
      }
    }

    return result_avp;
  }

  DiameterDictionary::AVPValueType
  DiameterDictionary::str_to_avp_value_type_(const std::string& avp_type_name)
  {
    if (avp_type_name == "octetstring")
    {
      return AVP_TYPE_OCTETSTRING;
    }

    return AVP_TYPE_UNDEFINED;
  }

  std::string
  DiameterDictionary::avp_value_type_to_string(AVPValueType avp_value_type)
  {
    if (avp_value_type == AVPValueType::AVP_TYPE_OCTETSTRING)
    {
      return "string";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_INTEGER32)
    {
      return "int32";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_INTEGER64)
    {
      return "int64";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_UNSIGNED32)
    {
      return "uint32";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_UNSIGNED64)
    {
      return "uint64";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_FLOAT32)
    {
      return "float32";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_FLOAT64)
    {
      return "float64";
    }
    else if (avp_value_type == AVPValueType::AVP_TYPE_GROUPED)
    {
      return "grouped";
    }

    return "undefined";
  }
}
