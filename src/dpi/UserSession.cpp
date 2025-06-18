#include "UserSession.hpp"

namespace dpi
{
  void
  UserSession::set_limits(
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
    unsigned long used_bytes)
  {
    UseLimitResult use_limit_result;

    auto use_it = used_limits_.find(session_key);
    auto limit_it = limits_.find(session_key);

    if (limit_it == limits_.end())
    {
      //std::cout << "use_limit: #1" << std::endl;
      use_limit_result.block = true;
      return use_limit_result;
    }

    //std::cout << "use_limit: #2" << std::endl;
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
      use_limit_result.revalidate_gx = true;
      use_limit_result.block = true;
    }

    if (limit_it->second.gy_limit.has_value() &&
      prev_used_bytes + used_bytes > *limit_it->second.gy_limit)
    {
      //std::cout << "use_limit: #3, prev_used_bytes = " << prev_used_bytes <<
      //  ", used_bytes = " << used_bytes <<
      //  ", gy_limit = " << *limit_it->second.gy_limit <<
      //  std::endl;
      use_limit_result.revalidate_gy = true;
      use_limit_result.block = true;
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
    unsigned long used_bytes)
  {
    //std::cout << "use_limit: used_bytes = " << used_bytes << std::endl;

    std::unique_lock<std::shared_mutex> guard(limits_lock_);
    UseLimitResult use_limit_result = use_limit_i_(session_key, now, used_bytes);

    if (use_limit_result.block)
    {
      use_limit_result = use_limit_i_(SessionKey(), now, used_bytes);
    }

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
}
