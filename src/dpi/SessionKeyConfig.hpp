#pragma once

#include <string>
#include <optional>
#include <vector>

#include <gears/Exception.hpp>
#include <gears/HashTable.hpp>

#include "SessionKey.hpp"
#include "SessionKeyEvaluator.hpp"

namespace dpi
{
  struct SessionKeyConfig
  {
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    // use only for allow/disallow traffic, contains rule with biggest priority:
    std::vector<SessionKeyEvaluator::SessionKeyRule> session_key_rules;

    static std::shared_ptr<SessionKeyConfig> read(const std::string_view& file);
  };

  using SessionKeyConfigPtr = std::shared_ptr<SessionKeyConfig>;
  using ConstSessionKeyConfigPtr = std::shared_ptr<const SessionKeyConfig>;
}
