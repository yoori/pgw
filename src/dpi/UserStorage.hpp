#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include <gears/Time.hpp>

#include "Logger.hpp"
#include "User.hpp"

namespace dpi
{
  class UserStorage
  {
  public:
    UserStorage(
      LoggerPtr event_logger,
      const SessionRuleConfig& session_rule_config);

    void set_event_logger(LoggerPtr event_logger);

    UserPtr add_user(std::string_view msisdn, uint32_t ip);

    void reset_user_ip(std::string_view msisdn);

    UserPtr get_user_by_ip(uint32_t ip, const Gears::Time& now) const;

    UserPtr get_user_by_msisdn(
      std::string_view msisdn,
      const Gears::Time& now)
      const;

  private:
    void remove_user_i_(const std::string& msisdn);

    void add_user_i_(UserPtr new_user);

    void log_event_(const std::string& msg);

  private:
    LoggerPtr event_logger_;
    SessionRuleConfig session_rule_config_;

    mutable std::shared_mutex lock_;
    std::unordered_map<uint32_t, UserPtr> users_by_ip_;
    std::unordered_map<std::string, UserPtr> users_by_msisdn_;
  };

  using UserStoragePtr = std::shared_ptr<UserStorage>;
}
