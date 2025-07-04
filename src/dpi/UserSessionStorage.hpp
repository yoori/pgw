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
    UserSessionStorage(LoggerPtr logger);

    UserSessionPtr add_user_session(
      const UserSessionTraits& user_session_traits,
      const UserPtr& user,
      bool replace = false);

    // remove session from storage
    UserSessionPtr remove_user_session(uint32_t ip);

    UserSessionPtr get_user_session_by_ip(uint32_t ip) const;

    UserSessionPtr get_user_session_by_gx_session_suffix(const std::string& gx_session_suffix) const;

  private:
    LoggerPtr logger_;

    mutable std::shared_mutex lock_;
    std::unordered_map<uint32_t, UserSessionPtr> user_sessions_by_ip_;
    std::unordered_map<std::string, UserSessionPtr> user_sessions_by_gx_session_suffix_;
  };

  using UserSessionStoragePtr = std::shared_ptr<UserSessionStorage>;
}
