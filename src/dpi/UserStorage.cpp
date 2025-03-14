#include <sstream>

#include "NetworkUtils.hpp"

#include "UserStorage.hpp"


namespace dpi
{
  // UserStorage impl.
  UserStorage::UserStorage(LoggerPtr event_logger, const SessionRuleConfig& session_rule_config)
    : event_logger_(std::move(event_logger)),
      session_rule_config_(session_rule_config)
  {}

  void
  UserStorage::set_event_logger(LoggerPtr event_logger)
  {
    event_logger_.swap(event_logger);
  }

  void
  UserStorage::add_user(std::string_view msisdn, uint32_t ip)
  {
    log_event_(
      std::string("add user msisdn = ") +
      std::string(msisdn) + ", ip = " + ipv4_address_to_string(ip));

    auto new_user = std::make_shared<User>(std::string(msisdn));
    new_user->set_ip(ip);

    std::unique_lock lock{lock_};
    remove_user_i_(new_user->msisdn());
    add_user_i_(new_user);
  }

  void
  UserStorage::remove_user(std::string_view msisdn)
  {
    std::string msisdn_val(msisdn);
    std::unique_lock lock{lock_};
    remove_user_i_(msisdn_val);
  }

  void
  UserStorage::add_user_i_(UserPtr new_user)
  {
    users_by_ip_.emplace(new_user->ip(), new_user);
    users_by_msisdn_.emplace(new_user->msisdn(), new_user);
  }

  void
  UserStorage::remove_user_i_(const std::string& msisdn_val)
  {
    auto it = users_by_msisdn_.find(msisdn_val);
    if (it != users_by_msisdn_.end())
    {
      users_by_ip_.erase(it->second->ip());
      users_by_msisdn_.erase(it);
    }
  }

  UserPtr
  UserStorage::get_user_by_ip(uint32_t ip, const Gears::Time& now) const
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
  UserStorage::get_user_by_msisdn(std::string_view msisdn, const Gears::Time& now) const
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
