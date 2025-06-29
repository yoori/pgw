#include <sstream>

#include <gears/Rand.hpp>

#include "UserSession.hpp"

namespace dpi
{
  UserSession::UserSession(const UserSessionTraits& traits, UserPtr user)
    : traits_(traits),
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
  UserSession::set_limits(
    const SetLimitArray& limits,
    const UsedLimitArray& decrease_used)
  {
    /*
    std::ostringstream ostr;
    ostr << "UserSession::set_limits(msisdn = " << traits_.msisdn << "):";

    for (const auto& limit: limits)
    {
      ostr << " " << limit.session_key.to_string() << " => " << limit.to_string();
    }

    std::cout << ostr.str() << std::endl;
    */

    LimitMap new_limits;
    for (const auto& limit: limits)
    {
      new_limits.emplace(limit.session_key, limit);
    }

    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    limits_.swap(new_limits);
    for (auto it = decrease_used.begin(); it != decrease_used.end(); ++it)
    {
      auto used_limit_it = used_limits_.find(it->session_key);
      if (used_limit_it != used_limits_.end())
      {
        if (used_limit_it->second.used_bytes >= it->used_bytes)
        {
          used_limit_it->second.used_bytes = used_limit_it->second.used_bytes - it->used_bytes;
        }
        else
        {
          used_limit_it->second.used_bytes = 0;
        }

        if (used_limit_it->second.used_bytes == 0)
        {
          used_limits_.erase(used_limit_it);
        }
      }
    }
  }

  UserSession::UseLimitResult
  UserSession::use_limit_i_(
    const SessionKey& session_key,
    const Gears::Time& now,
    unsigned long used_bytes,
    unsigned long used_output_bytes,
    unsigned long used_input_bytes)
  {
    UseLimitResult use_limit_result;

    auto use_it = used_limits_.find(session_key);
    auto limit_it = limits_.find(session_key);

    if (limit_it == limits_.end())
    {
      //std::cout << "use_limit: #1, session_key = " << session_key.to_string() << std::endl;
      use_limit_result.block = true;
      return use_limit_result;
    }

    //std::cout << "use_limit: #2" << session_key.to_string() << std::endl;
    use_limit_result.revalidate_gx |= (
      limit_it->second.gx_recheck_time.has_value() &&
      *(limit_it->second.gx_recheck_time) < now);
    use_limit_result.revalidate_gy |= (
      limit_it->second.gy_recheck_time.has_value() &&
      *(limit_it->second.gy_recheck_time) < now);

    const unsigned long prev_used_bytes = (
      use_it != used_limits_.end() ? use_it->second.used_bytes : 0);

    // check blocking
    /*
    std::cout << "gx_limit = " <<
      (limit_it->second.gx_limit.has_value() ?
        std::to_string(*limit_it->second.gx_limit) : std::string("null")) <<
      std::endl;
    */

    if (limit_it->second.gx_limit.has_value() &&
      prev_used_bytes + used_bytes > *limit_it->second.gx_limit)
    {
      if (prev_used_bytes <= *limit_it->second.gx_limit)
      {
        use_limit_result.revalidate_gx = true;
      }

      use_limit_result.block = true;
    }

    if (limit_it->second.gy_limit.has_value() &&
      prev_used_bytes + used_bytes > *limit_it->second.gy_limit)
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

    if (limit_it->second.gx_recheck_time != Gears::Time::ZERO &&
      last_limits_use_timestamp_ < now &&
      limit_it->second.gx_recheck_time <= now)
    {
      // jump over gx_recheck_time
      use_limit_result.revalidate_gx = true;
    }

    if (limit_it->second.gy_recheck_time != Gears::Time::ZERO &&
      last_limits_use_timestamp_ < now &&
      limit_it->second.gy_recheck_time <= now)
    {
      // jump over gx_recheck_time
      use_limit_result.revalidate_gy = true;
    }

    if (!use_limit_result.block)
    {
      used_limits_[session_key].used_bytes += used_bytes;
    }

    return use_limit_result;
  }

  UserSession::UseLimitResult
  UserSession::use_limit(
    const SessionKey& session_key,
    const Gears::Time& now,
    unsigned long used_bytes,
    unsigned long used_output_bytes,
    unsigned long used_input_bytes)
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
        SessionKey(),
        now,
        used_bytes,
        used_output_bytes,
        used_input_bytes);

      if (use_limit_result.block)
      {
        use_limit_result = use_limit_i_(
          SessionKey(),
          now,
          used_bytes,
          used_output_bytes,
          used_input_bytes);
      }
    }

    last_limits_use_timestamp_ = now;

    return use_limit_result;
  }

  UserSession::UsedLimitArray
  UserSession::get_used_limits() const
  {
    UsedLimitArray res;

    std::shared_lock<std::shared_mutex> guard(limits_lock_);
    for (auto it = used_limits_.begin(); it != used_limits_.end(); ++it)
    {
      res.emplace_back(UsedLimit(it->first, it->second.used_bytes));
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
