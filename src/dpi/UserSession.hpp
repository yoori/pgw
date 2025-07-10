#pragma once

#include <memory>
#include <string>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <set>

#include <gears/Time.hpp>
#include <gears/Hash.hpp>
#include <gears/HashTable.hpp>

#include "Types.hpp"
#include "UserSessionTraits.hpp"
#include "SessionKey.hpp"
#include "User.hpp"
#include "UserSessionPropertyContainer.hpp"
#include "OctetStats.hpp"

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
        const std::optional<unsigned long>& gx_recheck_limit,
        const std::optional<unsigned long>& gx_limit,
        const std::optional<Gears::Time>& gy_recheck_time,
        const std::optional<unsigned long>& gy_recheck_limit,
        const std::optional<unsigned long>& gy_limit);

      std::string to_string() const
      {
        return std::string("{") +
          "gx_recheck_time = " + (gx_recheck_time.has_value() ? std::to_string(gx_recheck_time->tv_sec) : std::string("none")) +
          ", gx_recheck_limit = " + (gx_recheck_limit.has_value() ? std::to_string(*gx_recheck_limit) : std::string("none")) +
          ", gx_limit = " + (gx_limit.has_value() ? std::to_string(*gx_limit) : std::string("none")) +
          ", gy_recheck_time = " + (gy_recheck_time.has_value() ? std::to_string(gy_recheck_time->tv_sec) : std::string("none")) +
          ", gy_recheck_limit = " + (gy_recheck_limit.has_value() ? std::to_string(*gy_recheck_limit) : std::string("none")) +
          ", gy_limit = " + (gy_limit.has_value() ? std::to_string(*gy_limit) : std::string("none")) +
          "}";
      }

      std::optional<Gears::Time> gx_recheck_time;
      std::optional<unsigned long> gx_recheck_limit;
      std::optional<unsigned long> gx_limit;
      std::optional<Gears::Time> gy_recheck_time;
      std::optional<unsigned long> gy_recheck_limit;
      std::optional<unsigned long> gy_limit;
    };

    struct SetLimit: public Limit
    {
      SetLimit();

      SetLimit(
        const SessionKey& session_key_val,
        const std::optional<Gears::Time>& gx_recheck_time,
        const std::optional<unsigned long>& gx_recheck_limit,
        const std::optional<unsigned long>& gx_limit,
        const std::optional<Gears::Time>& gy_recheck_time,
        const std::optional<unsigned long>& gy_recheck_limit,
        const std::optional<unsigned long>& gy_limit);

      SessionKey session_key;

      std::string to_string() const;
    };

    using SetLimitArray = std::vector<SetLimit>;

    struct UsedLimit: public OctetStats
    {
      UsedLimit() {};

      UsedLimit(const SessionKey& session_key_val, const OctetStats& used_bytes_val);

      SessionKey session_key;
    };

    using UsedLimitArray = std::vector<UsedLimit>;

    struct UseLimitResult
    {
      bool block = false;
      bool revalidate_gx = false;
      bool revalidate_gy = false;
      Gears::HashTable<SessionKey, UsageReportingReason> gy_reached_limits;
      bool closed = false;
      //bool revalidate = false; // set to true if revalidate time switched or limit.

      std::string to_string() const;
    };

  public:
    UserSession(
      const UserSessionTraits& traits,
      UserPtr user);

    ConstUserSessionTraitsPtr traits() const;

    void set_traits(const UserSessionTraits& traits);

    /*
    ConstUserSessionPropertyContainerPtr properties() const;

    void set_properties(const UserSessionPropertyValueMap& properties);
    */

    const UserPtr& user() const;

    void
    set_charging_rule_names(const std::unordered_set<std::string>& charging_rule_names);

    std::unordered_set<std::string>
    charging_rule_names() const;

    void
    set_limits(
      const SetLimitArray& limits,
      const UsedLimitArray& decrease_used = UsedLimitArray());

    UseLimitResult
    use_limit(
      const SessionKey& session_key,
      const Gears::Time& now,
      const OctetStats& octet_stats);

    UsedLimitArray
    get_gx_used_limits(bool own_stats = true);

    UsedLimitArray
    get_gy_used_limits(bool own_stats = true);

    std::pair<std::string, unsigned long>
    generate_gx_request_id();

    std::pair<std::string, unsigned long>
    generate_gy_request_id();

    const std::string&
    gx_session_suffix() const;

    void
    set_gx_inited(bool gx_inited);

    bool
    gx_inited() const;

    void
    set_gy_inited(bool gy_inited);

    bool
    gy_inited() const;

    bool
    is_closed() const;

    void
    close();

  private:
    struct LimitHolder
    {
      Gears::Time gx_recheck_time;
      unsigned long gx_limit = 0;
      Gears::Time gy_recheck_time;
      unsigned long gy_limit = 0;
    };

    using LimitMap = Gears::HashTable<SessionKey, Limit>;

    using UsedLimitHolderMap = Gears::HashTable<SessionKey, OctetStats>;

  private:
    UseLimitResult
    use_limit_i_(
      const SessionKey& session_key,
      const Gears::Time& now,
      const OctetStats& used_octets);

    void
    set_limits_i_(
      LimitMap& to_apply_limits,
      LimitMap& new_limits);

  private:
    UserPtr user_;

    std::string gx_session_id_suffix_;
    std::atomic<int> gx_request_id_;
    std::string gy_session_id_suffix_;
    std::atomic<int> gy_request_id_;

    mutable std::shared_mutex properties_lock_;
    ConstUserSessionPropertyContainerPtr properties_;

    mutable std::shared_mutex traits_lock_;
    ConstUserSessionTraitsPtr traits_;

    mutable std::shared_mutex charging_rule_lock_;
    std::unordered_set<std::string> charging_rule_names_;

    mutable std::shared_mutex diameter_lock_;
    bool gx_inited_ = true;
    bool gy_inited_ = true;

    mutable std::shared_mutex limits_lock_;
    bool is_closed_ = false;
    LimitMap limits_;
    Gears::Time last_limits_use_timestamp_;
    UsedLimitHolderMap gx_used_limits_;
    UsedLimitHolderMap gy_used_limits_;
  };

  using UserSessionPtr = std::shared_ptr<UserSession>;
}

namespace dpi
{
  inline std::string
  UserSession::UseLimitResult::to_string() const
  {
    return std::string("{block = ") + std::to_string(block) +
      ", revalidate_gx = " + std::to_string(revalidate_gx) +
      ", revalidate_gy = " + std::to_string(revalidate_gy) +
      ", closed = " + std::to_string(closed) +
      "}";
  }

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

  inline const UserPtr&
  UserSession::user() const
  {
    return user_;
  }

  inline ConstUserSessionTraitsPtr
  UserSession::traits() const
  {
    std::shared_lock<std::shared_mutex> guard(traits_lock_);
    return traits_;
  }

  inline
  UserSession::UsedLimit::UsedLimit(
    const SessionKey& session_key_val,
    const OctetStats& octet_stats)
    : session_key(session_key_val),
      OctetStats(octet_stats)
  {}

  // UserSession::Limit
  inline
  UserSession::Limit::Limit()
  {}

  inline
  UserSession::Limit::Limit(
    const std::optional<Gears::Time>& gx_recheck_time_val,
    const std::optional<unsigned long>& gx_recheck_limit_val,
    const std::optional<unsigned long>& gx_limit_val,
    const std::optional<Gears::Time>& gy_recheck_time_val,
    const std::optional<unsigned long>& gy_recheck_limit_val,
    const std::optional<unsigned long>& gy_limit_val)
    : gx_recheck_time(gx_recheck_time_val),
      gx_recheck_limit(gx_recheck_limit_val),
      gx_limit(gx_limit_val),
      gy_recheck_time(gy_recheck_time_val),
      gy_recheck_limit(gx_recheck_limit_val),
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
    const std::optional<unsigned long>& gx_recheck_limit_val,
    const std::optional<unsigned long>& gx_limit_val,
    const std::optional<Gears::Time>& gy_recheck_time_val,
    const std::optional<unsigned long>& gy_recheck_limit_val,
    const std::optional<unsigned long>& gy_limit_val)
    : Limit(
        gx_recheck_time_val,
        gx_recheck_limit_val,
        gx_limit_val,
        gy_recheck_time_val,
        gy_recheck_limit_val,
        gy_limit_val),
      session_key(session_key_val)
  {}
}
