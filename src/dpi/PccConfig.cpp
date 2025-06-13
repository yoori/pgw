#include <cstdint>
#include <fstream>

#include <jsoncons/json.hpp>

#include "PccConfig.hpp"

namespace dpi
{
  PccConfigPtr
  PccConfig::read(const std::string_view& file_path)
  {
    PccConfigPtr result_config = std::make_shared<PccConfig>();

    std::ifstream file(std::string(file_path).c_str());
    if (!file.is_open())
    {
      std::ostringstream ostr;
      ostr << "Can't open ip list by path: " << file_path;
      throw Exception(ostr.str());
    }

    jsoncons::json config_json = jsoncons::json::parse(file);

    if (config_json.contains("rules"))
    {
      for (const auto config_element_obj : config_json["rules"].array_range())
      {
        SessionKeyRule session_key_rule;

        const auto& session_key_obj = config_element_obj["session_key"];
        const std::string traffic_type = session_key_obj["traffic_type"].as_string();
        const std::string category_type = session_key_obj["category_type"].as_string();

        if (config_element_obj.contains("rating_groups"))
        {
          for (const auto& rg_obj : config_element_obj["rating_groups"].array_range())
          {
            session_key_rule.rating_groups.emplace_back(rg_obj.as_integer<uint32_t>());
          }

          std::sort(
            session_key_rule.rating_groups.begin(),
            session_key_rule.rating_groups.end());
          auto last = std::unique(
            session_key_rule.rating_groups.begin(),
            session_key_rule.rating_groups.end());
          session_key_rule.rating_groups.erase(
            last,
            session_key_rule.rating_groups.end());
        }

        if (config_element_obj.contains("monitoring_keys"))
        {
          for (const auto& mk_obj : config_element_obj["monitoring_keys"].array_range())
          {
            session_key_rule.monitoring_keys.emplace_back(
              mk_obj.as_integer<uint32_t>());
          }

          std::sort(
            session_key_rule.monitoring_keys.begin(),
            session_key_rule.monitoring_keys.end());
          auto last = std::unique(
            session_key_rule.monitoring_keys.begin(),
            session_key_rule.monitoring_keys.end());
          session_key_rule.monitoring_keys.erase(
            last,
            session_key_rule.monitoring_keys.end());
        }

        if (config_element_obj.contains("allow_traffic"))
        {
          session_key_rule.allow_traffic = config_element_obj["allow_traffic"].as_bool();
        }

        result_config->session_keys.emplace(
          SessionKey(traffic_type, category_type),
          session_key_rule);
      }
    }

    return result_config;
  }

  void
  PccConfig::save(const std::string_view& file_path) const
  {
    std::vector<jsoncons::json> rules_arr;
    for (auto it = session_keys.begin(); it != session_keys.end(); ++it)
    {
      const auto& session_key = it->first;
      const auto& session_key_rule = it->second;

      jsoncons::json session_key_json;
      session_key_json["traffic_type"] = session_key.traffic_type();
      session_key_json["category_type"] = session_key.category_type();

      jsoncons::json rule_obj;
      rule_obj["session_key"] = session_key_json;
      rule_obj["rating_groups"] = session_key_rule.rating_groups;
      rule_obj["monitoring_keys"] = session_key_rule.monitoring_keys;
      rule_obj["allow_traffic"] = session_key_rule.allow_traffic;
      rules_arr.emplace_back(std::move(rule_obj));
    }

    jsoncons::json save_json;
    save_json["rules"] = rules_arr;

    jsoncons::json_options json_print_options;
    json_print_options.escape_all_non_ascii(false);
    std::string res;
    jsoncons::encode_json(save_json, res, json_print_options, jsoncons::indenting::indent);
    
    std::ofstream file(std::string(file_path).c_str());
    if (!file.is_open())
    {
      std::ostringstream ostr;
      ostr << "Can't open ip list by path: " << file_path;
      throw Exception(ostr.str());
    }

    file.write(res.data(), res.size());
  }
}
