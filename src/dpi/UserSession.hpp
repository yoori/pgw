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

    const UserPtr& user() const;

  private:
    UserSessionTraits traits_;
    UserPtr user_;
  };

  using UserSessionPtr = std::shared_ptr<UserSession>;
}

namespace dpi
{
  inline
  UserSession::UserSession(const UserSessionTraits& traits, UserPtr user)
    : traits_(traits),
      user_(std::move(user))
  {}

  inline const UserPtr&
  UserSession::user() const
  {
    return user_;
  }

  inline const UserSessionTraits&
  UserSession::traits() const
  {
    return traits_;
  }
}
