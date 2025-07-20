#include <cstdint>
#include <fstream>

#include <jsoncons/json.hpp>

#include "SessionKeyConfig.hpp"

namespace dpi
{
  SessionKeyConfigPtr
  SessionKeyConfig::read(const std::string_view& file_path)
  {
    SessionKeyConfigPtr result_config = std::make_shared<SessionKeyConfig>();

    std::ifstream file(std::string(file_path).c_str());
    if (!file.is_open())
    {
      std::ostringstream ostr;
      ostr << "Can't open session key config by path: " << file_path;
      throw Exception(ostr.str());
    }

    jsoncons::json config_json = jsoncons::json::parse(file);

    if (config_json.contains("session_key_rules"))
    {
      for (const auto config_element_obj : config_json["session_key_rules"].array_range())
      {
        if (config_element_obj.contains("session_key"))
        {
          SessionKeyEvaluator::SessionKeyRule session_key_rule;

          {
            const auto& session_key_obj = config_element_obj["session_key"];
            const std::string traffic_type = session_key_obj["traffic_type"].as_string();
            const std::string category_type = session_key_obj["category_type"].as_string();
            session_key_rule.session_key = SessionKey(traffic_type, category_type);
          }

          if (config_element_obj.contains("priority"))
          {
            session_key_rule.priority = config_element_obj["priority"].as_integer<uint16_t>();
          }

          if (config_element_obj.contains("src_ip_mask"))
          {
            session_key_rule.src_ip_mask = SessionKeyEvaluator::string_to_ip_mask(
              config_element_obj["src_ip_mask"].as_string());
          }

          if (config_element_obj.contains("src_port"))
          {
            session_key_rule.src_port = config_element_obj["src_port"].as_integer<uint16_t>();
          }

          if (config_element_obj.contains("dst_ip_mask"))
          {
            session_key_rule.dst_ip_mask = SessionKeyEvaluator::string_to_ip_mask(
              config_element_obj["dst_ip_mask"].as_string());
          }

          if (config_element_obj.contains("dst_port"))
          {
            session_key_rule.dst_port = config_element_obj["dst_port"].as_integer<uint16_t>();
          }

          if (config_element_obj.contains("protocol"))
          {
            session_key_rule.protocol = config_element_obj["protocol"].as_string();
          }

          result_config->session_key_rules.emplace_back(std::move(session_key_rule));
        }
      }
    }

    return result_config;
  }
}
