#pragma once

#include <memory>
#include <string>
#include <optional>
#include <mutex>
#include <shared_mutex>

#include <gears/Time.hpp>
#include <gears/Hash.hpp>
#include <gears/HashTable.hpp>

#include "UserSessionTraits.hpp"
#include "SessionKey.hpp"
#include "User.hpp"

namespace dpi
{
  class UserSession
  {
  public:
    //using LimitHolderPtr = std::shared_ptr<LimitHolder>;

    struct Limit
    {
      Limit();

      Limit(
        const std::optional<Gears::Time>& gx_recheck_time,
        const std::optional<unsigned long>& gx_limit,
        const std::optional<Gears::Time>& gy_recheck_time,
        const std::optional<unsigned long>& gy_limit);

      std::optional<Gears::Time> gx_recheck_time;
      std::optional<unsigned long> gx_limit;
      std::optional<Gears::Time> gy_recheck_time;
      std::optional<unsigned long> gy_limit;
    };

    struct SetLimit: public Limit
    {
      SetLimit();

      SetLimit(
        const SessionKey& session_key_val,
        const std::optional<Gears::Time>& gx_recheck_time,
        const std::optional<unsigned long>& gx_limit,
        const std::optional<Gears::Time>& gy_recheck_time,
        const std::optional<unsigned long>& gy_limit);

      SessionKey session_key;

      std::string to_string() const;
    };

    using SetLimitArray = std::vector<SetLimit>;

    struct UsedLimit
    {
      UsedLimit() {};

      UsedLimit(const SessionKey& session_key_val, unsigned long used_bytes_val);

      SessionKey session_key;
      unsigned long used_bytes = 0;
      unsigned long used_output_bytes = 0;
      unsigned long used_input_bytes = 0;
    };

    using UsedLimitArray = std::vector<UsedLimit>;

    struct UseLimitResult
    {
      bool block = false;
      bool revalidate_gx = false;
      bool revalidate_gy = false;
    };

  public:
    UserSession(const UserSessionTraits& traits, UserPtr user);

    const UserSessionTraits& traits() const;

    const UserPtr& user() const;

    void set_limits(
      const SetLimitArray& limits,
      const UsedLimitArray& decrease_used = UsedLimitArray());

    UseLimitResult use_limit(
      const SessionKey& session_key,
      const Gears::Time& now,
      unsigned long used_bytes,
      unsigned long used_output_bytes,
      unsigned long used_input_bytes);

    UsedLimitArray
    get_used_limits() const;

  private:
    struct LimitHolder
    {
      Gears::Time gx_recheck_time;
      unsigned long gx_limit = 0;
      Gears::Time gy_recheck_time;
      unsigned long gy_limit = 0;
    };

    using LimitMap = Gears::HashTable<SessionKey, Limit>;

    struct UsedLimitHolder
    {
      unsigned long used_bytes = 0;
    };

    using UsedLimitHolderMap = Gears::HashTable<SessionKey, UsedLimitHolder>;

  private:
    UseLimitResult
    use_limit_i_(
      const SessionKey& session_key,
      const Gears::Time& now,
      unsigned long used_bytes,
      unsigned long used_output_bytes,
      unsigned long used_input_bytes);

  private:
    UserSessionTraits traits_;
    UserPtr user_;

    mutable std::shared_mutex limits_lock_;
    LimitMap limits_;
    UsedLimitHolderMap used_limits_;
  };

  using UserSessionPtr = std::shared_ptr<UserSession>;
}

namespace dpi
{
  inline std::string
  UserSession::SetLimit::to_string() const
  {
    return "{"
      "session_key = " + session_key.to_string() +
      ", gy_recheck_time = " + (
        gy_recheck_time.has_value() ? gy_recheck_time->gm_ft() : std::string("null")) +
      ", gy_limit = " + (
        gy_limit.has_value() ? std::to_string(*gy_limit) : std::string("null")) +
      "}";
  }

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

  inline
  UserSession::UsedLimit::UsedLimit(
    const SessionKey& session_key_val, unsigned long used_bytes_val)
    : session_key(session_key_val),
      used_bytes(used_bytes_val)
  {}

  // UserSession::Limit
  inline
  UserSession::Limit::Limit()
  {}

  inline
  UserSession::Limit::Limit(
    const std::optional<Gears::Time>& gx_recheck_time_val,
    const std::optional<unsigned long>& gx_limit_val,
    const std::optional<Gears::Time>& gy_recheck_time_val,
    const std::optional<unsigned long>& gy_limit_val)
    : gx_recheck_time(gx_recheck_time_val),
      gx_limit(gx_limit_val),
      gy_recheck_time(gy_recheck_time_val),
      gy_limit(gy_limit_val)
  {}

  // UserSession::SetLimit
  inline
  UserSession::SetLimit::SetLimit()
  {}

  inline
  UserSession::SetLimit::SetLimit(
    const SessionKey& session_key_val,
    const std::optional<Gears::Time>& gx_recheck_time_val,
    const std::optional<unsigned long>& gx_limit_val,
    const std::optional<Gears::Time>& gy_recheck_time_val,
    const std::optional<unsigned long>& gy_limit_val)
    : Limit(gx_recheck_time_val, gx_limit_val, gy_recheck_time_val, gy_limit_val),
      session_key(session_key_val)
  {}
}
