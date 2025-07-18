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
#include "SessionKeyRule.hpp"

namespace dpi
{
  // UserSessionStatsHolder : non thread safe
  class UserSessionStatsHolder
  {
  public:
    using OctetStatsPtr = std::shared_ptr<OctetStats>;
    using UsageBySessionKeyMap = Gears::HashTable<SessionKey, OctetStatsPtr>;
    using UsageByRuleIdMap = std::unordered_map<unsigned long, OctetStatsPtr>;

    // SessionKey => rule_id
    using AllowedSessionKeyMap = Gears::HashTable<SessionKey, unsigned long>;

    void
    allow_session_keys(const AllowedSessionKeyMap& allowed_session_keys);

    OctetStatsPtr
    get_usage_cell(const SessionKey& session_key);

    std::unordered_map<unsigned long, OctetStats>
    get_usage(bool own) const;

  private:
    UsageBySessionKeyMap usage_by_session_key_;
    UsageByRuleIdMap usage_by_rule_id_;
  };

  // UserSession
  class UserSession
  {
  public:
    //using LimitHolderPtr = std::shared_ptr<LimitHolder>;

    struct Limit
    {
      Limit();

      Limit(
        ConstSessionKeyRulePtr session_key_rule_val,
        const std::optional<Gears::Time>& gy_recheck_time_val,
        const std::optional<unsigned long>& gy_recheck_limit_val,
        const std::optional<unsigned long>& gy_limit_val);

      std::string to_string() const;

      ConstSessionKeyRulePtr session_key_rule;
      std::optional<Gears::Time> gy_recheck_time;
      std::optional<unsigned long> gy_recheck_limit;
      std::optional<unsigned long> gy_limit;
    };

    using SetLimitArray = std::vector<Limit>;

    struct UsedLimit: public OctetStats
    {
      UsedLimit() {};

      UsedLimit(
        unsigned long rule_id_val,
        const OctetStats& used_bytes_val,
        const std::optional<UsageReportingReason>& reporting_reason = std::nullopt);

      std::string
      to_string() const;

      unsigned long rule_id;
      std::optional<UsageReportingReason> reporting_reason;
    };

    using UsedLimitArray = std::vector<UsedLimit>;

    struct UseLimitResult
    {
      bool block = false;
      bool revalidate_gx = false;
      bool revalidate_gy = false;
      bool closed = false;

      Gears::HashTable<SessionKey, UsageReportingReason> gy_reached_limits;

      std::string to_string() const;
    };

    struct RevalidateResult
    {
      std::optional<Gears::Time> revalidate_gx_time;
      std::optional<Gears::Time> revalidate_gy_time;

      std::optional<Gears::Time> min_time() const;
    };

  public:
    UserSession(
      const UserSessionTraits& traits,
      UserPtr user);

    ConstUserSessionTraitsPtr traits() const;

    void set_traits(const UserSessionTraits& traits);

    const UserPtr& user() const;

    void
    set_charging_rule_names(const std::unordered_set<std::string>& charging_rule_names);

    std::unordered_set<std::string>
    charging_rule_names() const;

    void
    set_revalidate_gx_time(
      const std::optional<Gears::Time>& gx_revalidation_time);

    // add or update limits
    void
    set_gy_limits(
      const SetLimitArray& limits,
      const UsedLimitArray& decrease_used = UsedLimitArray());

    void
    remove_gy_limits(const std::vector<unsigned long>& rule_ids);

    RevalidateResult revalidation() const;

    UseLimitResult
    use_limit(
      const SessionKey& session_key,
      const Gears::Time& now,
      const OctetStats& octet_stats);

    UsedLimitArray
    get_gx_used_limits(bool own_stats = true);

    UsedLimitArray
    get_gy_used_limits(const Gears::Time& now, bool own_stats);

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
    using LimitPtr = std::shared_ptr<Limit>;
    using LimitMap = Gears::HashTable<SessionKey, LimitPtr>;
    using LimitByRuleIdMap = std::unordered_map<unsigned long, LimitPtr>;
    // using OctetStatsPtr = std::shared_ptr<OctetStats>;
    //using UsageBySessionKeyMap = Gears::HashTable<SessionKey, OctetStatsPtr>;
    //using UsageByRuleIdMap = std::unordered_map<unsigned long, OctetStatsPtr>;

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

    void
    fill_by_limits_by_rule_id_();

    static void
    fill_limit_by_session_key_i_(
      LimitMap& limit_by_session_key,
      const LimitByRuleIdMap& limit_by_rule_id);

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

    // limits and usage
    mutable std::shared_mutex limits_lock_;
    bool is_closed_ = false;
    std::optional<Gears::Time> revalidate_gx_time_;
    LimitMap limits_by_session_key_;
    LimitByRuleIdMap limits_by_rule_id_;
    UserSessionStatsHolder gx_usage_;
    UserSessionStatsHolder gy_usage_;
  };

  using UserSessionPtr = std::shared_ptr<UserSession>;
}

namespace dpi
{
  inline std::string
  UserSession::UsedLimit::to_string() const
  {
    return std::string("{rule_id = ") + std::to_string(rule_id) +
      ", total_octets = " + std::to_string(total_octets) +
      ", output_octets = " + std::to_string(output_octets) +
      ", input_octets = " + std::to_string(input_octets) +
      ", reporting_reason = " +
      (reporting_reason.has_value() ?
        std::to_string(static_cast<unsigned int>(*reporting_reason)) : std::string()) +
      "}";
  }

  inline std::optional<Gears::Time>
  UserSession::RevalidateResult::min_time() const
  {
    std::optional<Gears::Time> res;

    if (revalidate_gx_time.has_value())
    {
      res = *revalidate_gx_time;
    }

    if (revalidate_gy_time.has_value())
    {
      res = res.has_value() ? std::min(*revalidate_gy_time, *res) : *revalidate_gy_time;
    }

    return res;
  }

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
  UserSession::Limit::to_string() const
  {
    return std::string("{") +
      "rule_id = " + (session_key_rule ?
        std::to_string(session_key_rule->rule_id) : std::string("none")) +
      ", gy_recheck_time = " + (gy_recheck_time.has_value() ?
        std::to_string(gy_recheck_time->tv_sec) : std::string("none")) +
      ", gy_recheck_limit = " + (gy_recheck_limit.has_value() ?
        std::to_string(*gy_recheck_limit) : std::string("none")) +
      ", gy_limit = " + (gy_limit.has_value() ?
        std::to_string(*gy_limit) : std::string("none")) +
      "}";
  }

  /*
  inline std::string
  UserSession::SetLimit::to_string() const
  {
    std::string res = "{ session_keys = [";
    for (auto session_key_it = session_keys.begin(); session_key_it != session_keys.end();
      ++session_key_it)
    {
      res += (session_key_it != session_keys.begin() ? std::string(", ") : std::string()) +
        session_key_it->to_string();
    }
    res += "], gy_recheck_time = " + (
        gy_recheck_time.has_value() ? gy_recheck_time->gm_ft() : std::string("null")) +
      ", gy_limit = " + (
        gy_limit.has_value() ? std::to_string(*gy_limit) : std::string("null")) +
      "}";
    return res;
  }
  */

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
    unsigned long rule_id_val,
    const OctetStats& octet_stats_val,
    const std::optional<UsageReportingReason>& reporting_reason_val)
    : OctetStats(octet_stats_val),
      rule_id(rule_id_val),
      reporting_reason(reporting_reason_val)
  {}

  // UserSession::Limit
  inline
  UserSession::Limit::Limit()
  {}

  inline
  UserSession::Limit::Limit(
    ConstSessionKeyRulePtr session_key_rule_val,
    const std::optional<Gears::Time>& gy_recheck_time_val,
    const std::optional<unsigned long>& gy_recheck_limit_val,
    const std::optional<unsigned long>& gy_limit_val)
    : session_key_rule(std::move(session_key_rule_val)),
      gy_recheck_time(gy_recheck_time_val),
      gy_recheck_limit(gy_recheck_limit_val),
      gy_limit(gy_limit_val)
  {}

  inline std::string
  UserSession::Limit::to_string() const
  {
    return std::string("{") +
      "\"gy_recheck_time\": " + (
        gy_recheck_time.has_value() ?
        std::string("\"") + gy_recheck_time->gm_ft() + "\"" : std::string("none")) +
      ", \"gy_recheck_limit\": " + (
        gy_recheck_limit.has_value() ?
        std::to_string(*gy_recheck_limit) : std::string("none")) +
      ", \"gy_limit\": " + (
        gy_limit.has_value() ?
        std::to_string(*gy_limit) : std::string("none")) +
      "}";
  }

  // UserSession::SetLimit
  /*
  inline
  UserSession::SetLimit::SetLimit()
  {}

  inline
  UserSession::SetLimit::SetLimit(
    unsigned long rule_id_val,
    unsigned long priority_val,
    const SessionKeyArray& session_keys_val,
    const std::optional<Gears::Time>& gy_recheck_time_val,
    const std::optional<unsigned long>& gy_recheck_limit_val,
    const std::optional<unsigned long>& gy_limit_val)
    : Limit(
        gy_recheck_time_val,
        gy_recheck_limit_val,
        gy_limit_val),
      rule_id(rule_id_val),
      priority(priority_val),
      session_keys(session_keys_val)
  {}
  */
}
