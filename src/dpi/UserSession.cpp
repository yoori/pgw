#include <sstream>

#include <gears/Rand.hpp>

#include "UserSession.hpp"

namespace dpi
{
  // UserSessionStatsHolder impl
  std::unordered_map<unsigned long, OctetStats>
  UserSessionStatsHolder::get_usage(bool own) const
  {
    std::unordered_map<unsigned long, OctetStats> res;

    for (const auto& [rule_id, octet_stats_ptr] : usage_by_rule_id_)
    {
      if (!octet_stats_ptr->is_null())
      {
        res.emplace(rule_id, *octet_stats_ptr);
        if (own)
        {
          octet_stats_ptr->set_null();
        }
      }
    }

    return res;
  }

  UserSessionStatsHolder::OctetStatsPtr
  UserSessionStatsHolder::get_usage_cell(const SessionKey& session_key)
  {
    auto it = usage_by_session_key_.find(session_key);
    if (it != usage_by_session_key_.end())
    {
      return it->second;
    }

    return nullptr;
  }

  void
  UserSessionStatsHolder::allow_session_keys(const AllowedSessionKeyMap& allowed_session_keys)
  {
    UsageByRuleIdMap new_usage_by_rule_id;
    UsageBySessionKeyMap new_usage_by_session_key;

    for (const auto& [session_key, rule_id] : allowed_session_keys)
    {
      auto old_usage_by_rule_it = usage_by_rule_id_.find(rule_id);
      if (old_usage_by_rule_it != usage_by_rule_id_.end())
      {
        // rule usage already exists
        new_usage_by_rule_id.emplace(rule_id, old_usage_by_rule_it->second);
        new_usage_by_session_key.emplace(session_key, old_usage_by_rule_it->second);
      }
      else
      {
        // new rule id
        auto n_it = new_usage_by_rule_id.find(rule_id);
        if (n_it != new_usage_by_rule_id.end())
        {
          new_usage_by_session_key.emplace(session_key, n_it->second);
        }
        else
        {
          auto octet_stats_ptr = std::make_shared<OctetStats>();
          new_usage_by_rule_id.emplace(rule_id, octet_stats_ptr);
          new_usage_by_session_key.emplace(session_key, octet_stats_ptr);
        }
      }
    }

    usage_by_rule_id_.swap(new_usage_by_rule_id);
    usage_by_session_key_.swap(new_usage_by_session_key);
  }

  // UserSession impl
  UserSession::UserSession(
    const UserSessionTraits& traits,
    UserPtr user)
    : traits_(std::make_shared<const UserSessionTraits>(traits)),
      user_(std::move(user)),
      gx_request_id_(0),
      gy_request_id_(0)
  {
    gx_session_id_suffix_ = std::string(";") +
      std::to_string(Gears::safe_rand()) + ";0;" + std::to_string(Gears::safe_rand());
    gy_session_id_suffix_ = std::string(";") +
      std::to_string(Gears::safe_rand()) + ";0;" + std::to_string(Gears::safe_rand());
  }

  void
  UserSession::set_traits(const UserSessionTraits& traits)
  {
    ConstUserSessionTraitsPtr new_traits = std::make_shared<const UserSessionTraits>(traits);
    std::unique_lock<std::shared_mutex> guard(traits_lock_);
    traits_.swap(new_traits);
  }

  void
  UserSession::set_charging_rule_names(const std::unordered_set<std::string>& charging_rule_names)
  {
    std::unordered_set<std::string> charging_rule_names_val(charging_rule_names);
    std::unique_lock<std::shared_mutex> guard(charging_rule_lock_);
    charging_rule_names_.swap(charging_rule_names_val);
  }

  std::unordered_set<std::string>
  UserSession::charging_rule_names() const
  {
    std::shared_lock<std::shared_mutex> guard(charging_rule_lock_);
    return charging_rule_names_;
  }

  const std::string&
  UserSession::gx_session_suffix() const
  {
    return gx_session_id_suffix_;
  }

  std::pair<std::string, unsigned long>
  UserSession::generate_gx_request_id()
  {
    return std::make_pair(gx_session_id_suffix_, gx_request_id_++);
  }

  std::pair<std::string, unsigned long>
  UserSession::generate_gy_request_id()
  {
    return std::make_pair(gy_session_id_suffix_, gy_request_id_++);
  }

  void
  UserSession::set_gx_revalidation_time(const std::optional<Gears::Time>& gx_recheck_time)
  {
    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    gx_revalidation_time_ = gx_recheck_time;
  }

  void
  UserSession::set_gy_limits(
    const SetLimitArray& limits,
    const UsedLimitArray& decrease_used)
  {
    struct LimitHolder
    {
      LimitHolder() {}

      LimitHolder(unsigned int priority_val, unsigned long rule_id_val, LimitPtr limit_val)
        : priority(priority_val),
          rule_id(rule_id_val),
          limit(std::move(limit_val))
      {}

      unsigned int priority = 1;
      unsigned long rule_id;
      LimitPtr limit;
    };

    Gears::HashTable<SessionKey, LimitHolder> packed_new_limits;
    //std::unordered_map<unsigned long, std::shared_ptr<Limit>> packed_new_limits_by_rule_id;

    for (const auto& set_limit: limits)
    {
      auto limit_ptr = std::make_shared<Limit>(set_limit); //< construct without session_

      for (const auto& session_key : set_limit.session_keys)
      {
        auto prev_limit_it = packed_new_limits.find(session_key);
        if (prev_limit_it != packed_new_limits.end())
        {
          if (prev_limit_it->second.priority < set_limit.priority)
          {
            auto& change_limit_holder = packed_new_limits[session_key];
            change_limit_holder.priority = set_limit.priority;
            change_limit_holder.rule_id = set_limit.rule_id;
            change_limit_holder.limit = limit_ptr;
          }
        }
        else
        {
          packed_new_limits.emplace(
            session_key,
            LimitHolder(set_limit.priority, set_limit.rule_id, limit_ptr));
        }
      }
    }

    // Now we have mapping session_key => limit, used should have equal struct
    LimitMap new_limits;
    LimitByRuleIdMap limits_by_rule_id;
    UserSessionStatsHolder::AllowedSessionKeyMap allowed_session_keys;

    for (const auto& [session_key, packed_limit] : packed_new_limits)
    {
      new_limits.emplace(session_key, packed_limit.limit);
      allowed_session_keys.emplace(session_key, packed_limit.rule_id);
      limits_by_rule_id.emplace(packed_limit.rule_id, packed_limit.limit);
    }

    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    limits_.swap(new_limits);
    limits_by_rule_id_.swap(limits_by_rule_id);
    gx_usage_.allow_session_keys(allowed_session_keys);
    gy_usage_.allow_session_keys(allowed_session_keys);
  }

  UserSession::UseLimitResult
  UserSession::use_limit(
    const SessionKey& session_key,
    const Gears::Time& now,
    const OctetStats& used_octets)
  {
    //std::cout << "use_limit: used_bytes = " << used_bytes << std::endl;

    std::unique_lock<std::shared_mutex> guard(limits_lock_);

    UseLimitResult use_limit_result;

    if (is_closed_)
    {
      use_limit_result.closed = true;
      use_limit_result.block = true;
    }
    else
    {
      use_limit_result = use_limit_i_(
        session_key,
        now,
        used_octets);

      if (use_limit_result.block)
      {
        use_limit_result = use_limit_i_(
          SessionKey(),
          now,
          used_octets);
      }
    }

    return use_limit_result;
  }

  UserSession::RevalidateResult
  UserSession::revalidation() const
  {
    RevalidateResult revalidate_result;

    {
      std::shared_lock<std::shared_mutex> guard(limits_lock_);

      for (const auto& [_, limit_ptr] : limits_)
      {
        if (limit_ptr->gy_recheck_time.has_value())
        {
          revalidate_result.revalidate_gy_time = limit_ptr->gy_recheck_time.has_value() ?
            std::min(*revalidate_result.revalidate_gy_time, *(limit_ptr->gy_recheck_time)) :
            *(limit_ptr->gy_recheck_time);
        }
      }
    }

    return revalidate_result;
  }

  UserSession::UseLimitResult
  UserSession::use_limit_i_(
    const SessionKey& session_key,
    const Gears::Time& now,
    const OctetStats& used_octets)
  {
    //std::cout << "UserSession::use_limit_i_()" << std::endl;

    UseLimitResult use_limit_result;

    auto limit_it = limits_.find(session_key);

    if (limit_it == limits_.end())
    {
      //std::cout << "use_limit: #1, session_key = " << session_key.to_string() << std::endl;
      use_limit_result.block = true;
      return use_limit_result;
    }

    // for limits check we use only gy stats
    auto use_cell = gy_usage_.get_usage_cell(session_key);

    if (!use_cell)
    {
      use_limit_result.block = true;
      return use_limit_result;
    }

    const unsigned long prev_used_bytes = use_cell->total_octets;

    /*
    std::cout << "use_limit: #2" << session_key.to_string() <<
      ", prev_used_bytes = " << prev_used_bytes <<
      ", gy_limit = " << (
        limit_it->second->gy_limit.has_value() ?
        std::to_string(*limit_it->second->gy_limit) : "none") <<
      std::endl;
    */

    // check blocking
    if (limit_it->second->gy_limit.has_value() &&
      prev_used_bytes + used_octets.total_octets > *(limit_it->second->gy_limit))
    {
      /*
      std::cout << "use_limit: #3, prev_used_bytes = " << prev_used_bytes <<
        ", used_bytes = " << use_cell->total_octets <<
        ", gy_limit = " << *limit_it->second->gy_limit <<
        std::endl;
      */

      if (prev_used_bytes <= *(limit_it->second->gy_limit))
      {
        use_limit_result.revalidate_gy = true;
      }

      use_limit_result.block = true;
    }

    if (!use_limit_result.block)
    {

      if (limit_it->second->gy_recheck_limit.has_value() &&
        prev_used_bytes + use_cell->total_octets > *(limit_it->second->gy_recheck_limit) &&
        prev_used_bytes <= *(limit_it->second->gy_recheck_limit))
      {
        use_limit_result.revalidate_gy = true;
      }

      /*
      if (limit_it->second.gy_recheck_time.has_value() &&
        *limit_it->second.gy_recheck_time != Gears::Time::ZERO &&
        *limit_it->second.gy_recheck_time <= now)
      {
        use_limit_result.revalidate_gy = true;
      }
      */
    }

    if (!use_limit_result.block)
    {
      *use_cell += used_octets;
      auto gx_use_cell = gx_usage_.get_usage_cell(session_key);
      assert(gx_use_cell);
      *gx_use_cell += used_octets;
    }

    return use_limit_result;
  }

  UserSession::UsedLimitArray
  UserSession::get_gx_used_limits(bool own_stats)
  {
    UsedLimitArray res;

    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    auto usage_stats = gx_usage_.get_usage(own_stats);

    for (const auto& [rule_id, octet_stats] : usage_stats)
    {
      res.emplace_back(UsedLimit(rule_id, octet_stats, std::nullopt));
    }

    /*
    if (own_stats)
    {
      gx_used_limits_.clear();
    }
    */

    return res;
  }

  UserSession::UsedLimitArray
  UserSession::get_gy_used_limits(const Gears::Time& now, bool own_stats)
  {
    UsedLimitArray res;

    std::unique_lock<std::shared_mutex> guard(limits_lock_);

    auto usage_stats = gy_usage_.get_usage(own_stats);

    for (const auto& [rule_id, octet_stats] : usage_stats)
    {
      // evaluate used limit status
      std::optional<UsageReportingReason> reporting_reason;
      auto limit_it = limits_by_rule_id_.find(rule_id);
      if (limit_it != limits_by_rule_id_.end())
      {
        const unsigned used_bytes = octet_stats.total_octets;

        /*
        std::cout << "R STEP: used_bytes = " << used_bytes <<
          ", gy_limit = " << (
            limit_it->second->gy_limit.has_value() ?
            std::to_string(*(limit_it->second->gy_limit)) :
            "none") << std::endl;
        */

        if (limit_it->second->gy_limit.has_value() &&
          used_bytes >= *(limit_it->second->gy_limit))
        {
          reporting_reason = UsageReportingReason::QUOTA_EXHAUSTED;
        }
        else if (limit_it->second->gy_recheck_limit.has_value() &&
          used_bytes >= *(limit_it->second->gy_recheck_limit))
        {
          reporting_reason = UsageReportingReason::THRESHOLD;
        }
        else if (limit_it->second->gy_recheck_time.has_value() &&
          now >= *(limit_it->second->gy_recheck_time))
        {
          reporting_reason = UsageReportingReason::VALIDITY_TIME;
        }
      }

      res.emplace_back(UsedLimit(rule_id, octet_stats, reporting_reason));
    }

    /*
    if (own_stats)
    {
      gy_used_limits_.clear();
    }
    */

    return res;
  }

  bool
  UserSession::is_closed() const
  {
    std::shared_lock<std::shared_mutex> guard(limits_lock_);
    return is_closed_;
  }

  void
  UserSession::close()
  {
    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    is_closed_ = true;
  }

  void
  UserSession::set_gx_inited(bool gx_inited)
  {
    std::unique_lock<std::shared_mutex> guard(diameter_lock_);
    gx_inited_ = gx_inited;
  }

  bool
  UserSession::gx_inited() const
  {
    std::shared_lock<std::shared_mutex> guard(diameter_lock_);
    return gx_inited_;
  }

  void
  UserSession::set_gy_inited(bool gy_inited)
  {
    std::unique_lock<std::shared_mutex> guard(diameter_lock_);
    gy_inited_ = gy_inited;
  }

  bool
  UserSession::gy_inited() const
  {
    std::shared_lock<std::shared_mutex> guard(diameter_lock_);
    return gy_inited_;
  }
}
