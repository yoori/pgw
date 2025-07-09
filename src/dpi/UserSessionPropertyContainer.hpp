#pragma once

#include <unordered_map>
#include <memory>

#include "JsonUtils.hpp"
#include "Value.hpp"

namespace dpi
{
  using UserSessionPropertyValueMap = std::unordered_map<std::string, Value>;

  // UserSessionPropertyContainer: contains named values linked to user session.
  // Used in diffecent cases for get session values (for send to diameter as example).
  //
  struct UserSessionPropertyContainer
  {
    jsoncons::json to_json() const;

    std::string to_string() const;

    UserSessionPropertyValueMap values;
  };

  using ConstUserSessionPropertyContainerPtr = std::shared_ptr<UserSessionPropertyContainer>;
  using UserSessionPropertyContainerPtr = std::shared_ptr<UserSessionPropertyContainer>;
}
