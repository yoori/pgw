#include <sstream>

#include <gears/Time.hpp>

#include "NetworkUtils.hpp"

#include "UserStorage.hpp"


namespace dpi
{
  std::string
  UserStorage::User::to_string() const
  {
    return std::string("{msisdn = ") + msisdn +
      ", ip = " + ipv4_address_to_string(ip) + "}";
  }

  UserStorage::UserStorage(LoggerPtr event_logger)
    : event_logger_(std::move(event_logger))
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

    auto new_user = std::make_shared<User>();
    new_user->msisdn = msisdn;
    new_user->ip = ip;

    std::unique_lock lock{lock_};
    remove_user_i_(new_user->msisdn);
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
    users_by_ip_.emplace(new_user->ip, new_user);
    users_by_msisdn_.emplace(new_user->msisdn, new_user);
  }

  void
  UserStorage::remove_user_i_(const std::string& msisdn_val)
  {
    auto it = users_by_msisdn_.find(msisdn_val);
    if (it != users_by_msisdn_.end())
    {
      users_by_ip_.erase(it->second->ip);
      users_by_msisdn_.erase(it);
    }
  }

  UserStorage::UserPtr
  UserStorage::get_user_by_ip(uint32_t ip) const
  {
    std::shared_lock lock{lock_};

    auto it = users_by_ip_.find(ip);
    if (it != users_by_ip_.end())
    {
      return it->second;
    }

    return UserPtr();
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
