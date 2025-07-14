#include <sstream>

#include <gears/Rand.hpp>

#include "UserSession.hpp"

namespace dpi
{
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

  /*
  ConstUserSessionPropertyContainerPtr
  UserSession::properties() const
  {
    std::unique_lock<std::shared_mutex> guard(properties_lock_);
    return properties_;
  }

  void
  UserSession::set_properties(const UserSessionPropertyValueMap& properties)
  {
    std::shared_ptr<UserSessionPropertyContainer> new_properties;

    std::unique_lock<std::shared_mutex> guard(properties_lock_);
    new_properties = std::make_shared<UserSessionPropertyContainer>(*properties_);
    for (const auto& [name, value] : properties)
    {
      new_properties->values[name] = value;
    }
    properties_.swap(new_properties);
  }
  */

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
    LimitMap new_limits;
    for (const auto& limit: limits)
    {
      new_limits.emplace(limit.session_key, limit);
    }

    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    limits_.swap(new_limits);
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

      for (const auto& [_, limit] : limits_)
      {
        if (limit.gy_recheck_time.has_value())
        {
          revalidate_result.revalidate_gy_time = limit.gy_recheck_time.has_value() ?
            std::min(*revalidate_result.revalidate_gy_time, *limit.gy_recheck_time) :
            *limit.gy_recheck_time;
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

    auto use_it = gy_used_limits_.find(session_key);
    auto limit_it = limits_.find(session_key);

    if (limit_it == limits_.end())
    {
      //std::cout << "use_limit: #1, session_key = " << session_key.to_string() << std::endl;
      use_limit_result.block = true;
      return use_limit_result;
    }

    //std::cout << "use_limit: #2" << session_key.to_string() << std::endl;
    const unsigned long prev_used_bytes = (
      use_it != gy_used_limits_.end() ? use_it->second.total_octets : 0);

    // check blocking
    if (limit_it->second.gy_limit.has_value() &&
      prev_used_bytes + used_octets.total_octets > *limit_it->second.gy_limit)
    {
      /*
      std::cout << "use_limit: #3, prev_used_bytes = " << prev_used_bytes <<
        ", used_bytes = " << used_bytes <<
        ", gy_limit = " << *limit_it->second.gy_limit <<
        std::endl;
      */
      if (prev_used_bytes <= *limit_it->second.gy_limit)
      {
        use_limit_result.revalidate_gy = true;
      }

      use_limit_result.block = true;
    }

    if (!use_limit_result.block)
    {

      if (limit_it->second.gy_recheck_limit.has_value() &&
        prev_used_bytes + used_octets.total_octets > *limit_it->second.gy_recheck_limit &&
        prev_used_bytes <= *limit_it->second.gy_recheck_limit)
      {
        use_limit_result.revalidate_gy = true;
      }

      if (limit_it->second.gy_recheck_time.has_value() &&
        *limit_it->second.gy_recheck_time != Gears::Time::ZERO &&
        *limit_it->second.gy_recheck_time <= now)
      {
        use_limit_result.revalidate_gy = true;
      }
    }

    if (!use_limit_result.block)
    {
      gx_used_limits_[session_key] += used_octets;
      gy_used_limits_[session_key] += used_octets;
    }

    return use_limit_result;
  }

  UserSession::UsedLimitArray
  UserSession::get_gx_used_limits(bool own_stats)
  {
    UsedLimitArray res;

    std::shared_lock<std::shared_mutex> guard(limits_lock_);
    for (auto it = gx_used_limits_.begin(); it != gx_used_limits_.end(); ++it)
    {
      res.emplace_back(UsedLimit(it->first, it->second));
    }

    if (own_stats)
    {
      gx_used_limits_.clear();
    }

    return res;
  }

  UserSession::UsedLimitArray
  UserSession::get_gy_used_limits(const Gears::Time& now, bool own_stats)
  {
    UsedLimitArray res;

    std::shared_lock<std::shared_mutex> guard(limits_lock_);
    for (auto it = gy_used_limits_.begin(); it != gy_used_limits_.end(); ++it)
    {
      // evaluate used limit status
      std::optional<UsageReportingReason> reporting_reason;
      auto limit_it = limits_.find(it->first);
      if (limit_it != limits_.end())
      {
        const unsigned used_bytes = it->second.total_octets;

        if (limit_it->second.gy_limit.has_value() && used_bytes >= *limit_it->second.gy_limit)
        {
          reporting_reason = UsageReportingReason::QUOTA_EXHAUSTED;
        }
        else if (limit_it->second.gy_recheck_limit.has_value() && used_bytes >= *limit_it->second.gy_recheck_limit)
        {
          reporting_reason = UsageReportingReason::QUOTA_EXHAUSTED;
        }
        else if (limit_it->second.gy_recheck_time.has_value() &&
          now >= *limit_it->second.gy_recheck_time)
        {
          reporting_reason = UsageReportingReason::VALIDITY_TIME;
        }
      }

      res.emplace_back(UsedLimit(it->first, it->second, reporting_reason));
    }

    if (own_stats)
    {
      gy_used_limits_.clear();
    }

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
