#pragma once

#include <string>
#include <optional>
#include <vector>

#include <gears/Exception.hpp>
#include <gears/HashTable.hpp>

#include "SessionKey.hpp"
#include "SessionKeyRule.hpp"

namespace dpi
{
  struct PccConfig
  {
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    // use only for allow/disallow traffic, contains rule with biggest priority:
    Gears::HashTable<SessionKey, ConstSessionKeyRulePtr> session_rule_by_session_key;
    std::unordered_map<unsigned long, ConstSessionKeyRulePtr> session_keys;
    std::unordered_map<std::string, ConstSessionKeyRulePtr> session_rule_by_charging_name;
    std::unordered_map<unsigned long, ConstSessionKeyRulePtr> session_rule_by_rating_group;

    static std::shared_ptr<PccConfig> read(const std::string_view& file);

    void save(const std::string_view& file) const;
  };

  using PccConfigPtr = std::shared_ptr<PccConfig>;
  using ConstPccConfigPtr = std::shared_ptr<const PccConfig>;
}
