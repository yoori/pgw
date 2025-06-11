#include <sstream>

#include "NetworkUtils.hpp"

#include "UserSessionStorage.hpp"


namespace dpi
{
  // UserStorage impl.
  UserSessionStorage::UserSessionStorage(LoggerPtr event_logger, const SessionRuleConfig& session_rule_config)
    : event_logger_(std::move(event_logger))
  {}

  void
  UserSessionStorage::set_event_logger(LoggerPtr event_logger)
  {
    event_logger_.swap(event_logger);
  }

  UserSessionPtr
  UserSessionStorage::add_user_session(uint32_t ip)
  {
    std::string msisdn_val(msisdn);
    std::string imsi_val(imsi);
    UserPtr added_user;

    {
      std::unique_lock lock{lock_};

      auto it = users_by_msisdn_.find(msisdn_val);
      if (it != users_by_msisdn_.end())
      {
        added_user = it->second;
        uint32_t prev_ip = added_user->ip();

        if (prev_ip != ip && ip != 0)
          // don't change ip if it is defined
        {
          if (prev_ip != 0)
          {
            users_by_ip_.erase(prev_ip);
          }

          if (ip != 0)
          {
            users_by_ip_.emplace(ip, added_user);
          }

          added_user->set_ip(ip);
        }
      }
      else
      {
        added_user = std::make_shared<User>(msisdn_val, imsi_val, ip);

        if (ip != 0)
        {
          users_by_ip_.emplace(ip, added_user);
        }

        users_by_msisdn_.emplace(msisdn_val, added_user);
      }
    }

    log_event_(
      std::string("add user msisdn = ") +
      std::string(msisdn) + ", ip = " + ipv4_address_to_string(added_user->ip()));

    return added_user;
  }

  UserSessionPtr
  UserStorage::remove_user_session(uint32_t ip) const
  {
    std::shared_lock lock{lock_};

    auto it = users_by_ip_.find(ip);
    if (it == users_by_ip_.end())
    {
      return UserPtr();
    }

    UserPtr result_user = it->second;
    lock.unlock();

    result_user->clear_expired_sessions(session_rule_config_, now);
    return result_user;
  }

  UserPtr
  UserStorage::get_user_session_by_ip(uint32_t ip, const Gears::Time& now) const
  {
    const std::string msisdn_val(msisdn);

    std::shared_lock lock{lock_};

    auto it = users_by_msisdn_.find(msisdn_val);
    if (it == users_by_msisdn_.end())
    {
      return UserPtr();
    }

    UserPtr result_user = it->second;
    lock.unlock();

    result_user->clear_expired_sessions(session_rule_config_, now);
    return result_user;
  }

  void UserStorage::log_event_(const std::string& msg)
  {
    if (event_logger_)
    {
      std::ostringstream ostr;
      ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] [sber-telecom] USER-EVENT: " <<
        msg << std::endl;
      event_logger_->log(ostr.str());
    }
  }
}
