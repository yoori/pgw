#pragma once

#include <memory>
#include <string>
#include <optional>
#include <mutex>

#include <gears/Time.hpp>
#include <gears/Hash.hpp>
#include <gears/HashTable.hpp>

#include "UserSessionTraits.hpp"

namespace dpi
{
  class UserSession
  {
  public:
    UserSession(const UserSessionTraits& traits, UserPtr user);

    const UserSessionTraits& traits() const;

  private:
    UserSessionTraits traits_;
    UserPtr user_;
  };

  using UserSessionPtr = std::shared_ptr<UserSession>;
}

namespace dpi
{
  inline std::string
  UserSessionTraits::to_string() const
  {
  }
}
