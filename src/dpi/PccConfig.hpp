#pragma once

#include <string>
#include <optional>
#include <vector>

#include <gears/Exception.hpp>
#include <gears/HashTable.hpp>

#include "SessionKey.hpp"

namespace dpi
{
  struct PccConfig
  {
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    struct SessionKeyRule
    {
      unsigned long rule_id = 1;
      unsigned long priority = 1;
      std::vector<SessionKey> session_keys;
      std::string charging_rule_name;
      std::vector<unsigned long> monitoring_keys;
      std::vector<unsigned long> rating_groups;
      bool allow_traffic = false; //< Allow traffic ignoring Gx, Gy rules.
      bool check_gx = true;
      bool check_gy = true;
    };

    // use only for allow/disallow traffic, contains rule with biggest priority:
    Gears::HashTable<SessionKey, SessionKeyRule> session_rule_by_session_key;
    std::unordered_map<unsigned long, SessionKeyRule> session_keys;
    std::unordered_map<std::string, SessionKeyRule> session_rule_by_charging_name;
    std::unordered_map<unsigned long, SessionKeyRule> session_rule_by_rating_group;

    static std::shared_ptr<PccConfig> read(const std::string_view& file);

    void save(const std::string_view& file) const;
  };

  using PccConfigPtr = std::shared_ptr<PccConfig>;
  using ConstPccConfigPtr = std::shared_ptr<const PccConfig>;
}
