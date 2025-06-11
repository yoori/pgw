#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include <gears/Time.hpp>

#include "Logger.hpp"
#include "User.hpp"
#include "UserSession.hpp"

namespace dpi
{
  class UserSessionStorage
  {
  public:
    UserSessionStorage(
      LoggerPtr event_logger,
      const SessionRuleConfig& session_rule_config);

    UserSessionPtr add_user_session(uint32_t ip);

    // remove session from storage
    UserSessionPtr remove_user_session(uint32_t ip);

    UserSessionPtr get_user_session_by_ip(uint32_t ip, const Gears::Time& now) const;

  private:
    LoggerPtr event_logger_;
    SessionRuleConfig session_rule_config_;

    mutable std::shared_mutex lock_;
    std::unordered_map<uint32_t, UserSessionPtr> user_sessions_by_ip_;
  };

  using UserSessionStoragePtr = std::shared_ptr<UserSessionStorage>;
}
