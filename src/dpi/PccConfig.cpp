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
      ostr << "Can't open pcc config by path: " << file_path;
      throw Exception(ostr.str());
    }

    jsoncons::json config_json = jsoncons::json::parse(file);

    if (config_json.contains("rules"))
    {
      unsigned long rule_id = 1;

      for (const auto config_element_obj : config_json["rules"].array_range())
      {
        SessionKeyRulePtr session_key_rule = std::make_shared<SessionKeyRule>();
        session_key_rule->rule_id = rule_id;

        if (config_element_obj.contains("charging_rule_name"))
        {
          session_key_rule->charging_rule_name = config_element_obj["charging_rule_name"].as_string();
        }

        if (config_element_obj.contains("rating_groups"))
        {
          for (const auto& rg_obj : config_element_obj["rating_groups"].array_range())
          {
            session_key_rule->rating_groups.emplace_back(rg_obj.as_integer<uint32_t>());
          }

          std::sort(
            session_key_rule->rating_groups.begin(),
            session_key_rule->rating_groups.end());
          auto last = std::unique(
            session_key_rule->rating_groups.begin(),
            session_key_rule->rating_groups.end());
          session_key_rule->rating_groups.erase(
            last,
            session_key_rule->rating_groups.end());
        }

        if (config_element_obj.contains("monitoring_keys"))
        {
          for (const auto& mk_obj : config_element_obj["monitoring_keys"].array_range())
          {
            session_key_rule->monitoring_keys.emplace_back(
              mk_obj.as_integer<uint32_t>());
          }

          std::sort(
            session_key_rule->monitoring_keys.begin(),
            session_key_rule->monitoring_keys.end());
          auto last = std::unique(
            session_key_rule->monitoring_keys.begin(),
            session_key_rule->monitoring_keys.end());
          session_key_rule->monitoring_keys.erase(
            last,
            session_key_rule->monitoring_keys.end());
        }

        if (config_element_obj.contains("allow_traffic"))
        {
          session_key_rule->allow_traffic = config_element_obj["allow_traffic"].as_bool();
        }

        if (config_element_obj.contains("check_gx"))
        {
          session_key_rule->check_gx = config_element_obj["check_gx"].as_bool();
        }

        if (config_element_obj.contains("check_gy"))
        {
          session_key_rule->check_gy = config_element_obj["check_gy"].as_bool();
        }

        if (config_element_obj.contains("priority"))
        {
          session_key_rule->priority = config_element_obj["priority"].as_integer<uint16_t>();
        }

        for (const auto& session_key_obj : config_element_obj["session_keys"].array_range())
        {
          const std::string traffic_type = session_key_obj["traffic_type"].as_string();
          const std::string category_type = session_key_obj["category_type"].as_string();
          session_key_rule->session_keys.emplace_back(SessionKey(traffic_type, category_type));
        }

        for (const auto& session_key : session_key_rule->session_keys)
        {
          {
            auto it = result_config->session_rule_by_session_key.find(session_key);
            if (it != result_config->session_rule_by_session_key.end())
            {
              if (it->second->priority < session_key_rule->priority)
              {
                result_config->session_rule_by_session_key[session_key] = session_key_rule;
              }
            }
            else
            {
              result_config->session_rule_by_session_key.emplace(session_key, session_key_rule);
            }
          }
        }

        result_config->session_keys.emplace(session_key_rule->rule_id, session_key_rule);

        if (!session_key_rule->charging_rule_name.empty())
        {
          result_config->session_rule_by_charging_name.emplace(
            session_key_rule->charging_rule_name,
            session_key_rule);
        }

        for (const auto& rating_group_id : session_key_rule->rating_groups)
        {
          result_config->session_rule_by_rating_group.emplace(
            rating_group_id,
            session_key_rule);
        }

        ++rule_id;
      }
    }

    return result_config;
  }

  void
  PccConfig::save(const std::string_view& file_path) const
  {
    std::vector<jsoncons::json> rules_arr;
    for (const auto& [_, session_key_rule] : session_keys)
    {
      std::vector<jsoncons::json> session_keys_json;
      for (const auto& session_key : session_key_rule->session_keys)
      {
        jsoncons::json session_key_json;
        session_key_json["traffic_type"] = session_key.traffic_type();
        session_key_json["category_type"] = session_key.category_type();
        session_keys_json.emplace_back(std::move(session_key_json));
      }

      jsoncons::json rule_obj;
      rule_obj["priority"] = session_key_rule->priority;
      rule_obj["session_keys"] = session_keys_json;
      rule_obj["rating_groups"] = session_key_rule->rating_groups;
      rule_obj["monitoring_keys"] = session_key_rule->monitoring_keys;
      rule_obj["allow_traffic"] = session_key_rule->allow_traffic;
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
