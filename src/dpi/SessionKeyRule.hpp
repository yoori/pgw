#pragma once

#include <memory>
#include <string>
#include <vector>

#include "SessionKey.hpp"

namespace dpi
{
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

  using SessionKeyRulePtr = std::shared_ptr<SessionKeyRule>;
  using ConstSessionKeyRulePtr = std::shared_ptr<const SessionKeyRule>;
}
