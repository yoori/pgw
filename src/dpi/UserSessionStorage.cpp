#include <sstream>

#include "NetworkUtils.hpp"

#include "UserSessionStorage.hpp"


namespace dpi
{
  // UserStorage impl.
  UserSessionStorage::UserSessionStorage(LoggerPtr logger)
    : logger_(std::move(logger))
  {}

  UserSessionPtr
  UserSessionStorage::add_user_session(
    const UserSessionTraits& user_session_traits,
    const UserPtr& user)
  {
    UserSessionPtr added_session;

    {
      std::unique_lock lock{lock_};

      auto it = user_sessions_by_ip_.find(user_session_traits.framed_ip_address);
      if (it != user_sessions_by_ip_.end())
      {
        added_session = it->second;
      }
      else
      {
        added_session = std::make_shared<UserSession>(UserSessionTraits(), user);
        user_sessions_by_ip_.emplace(
          user_session_traits.framed_ip_address,
          added_session);
      }
    }

    return added_session;
  }

  UserSessionPtr
  UserSessionStorage::remove_user_session(uint32_t ip)
  {
    std::unique_lock lock{lock_};

    auto it = user_sessions_by_ip_.find(ip);
    if (it != user_sessions_by_ip_.end())
    {
      auto res = it->second;
      user_sessions_by_ip_.erase(it);
      return res;
    }

    return UserSessionPtr();
  }

  UserSessionPtr
  UserSessionStorage::get_user_session_by_ip(uint32_t ip) const
  {
    std::shared_lock lock{lock_};

    auto it = user_sessions_by_ip_.find(ip);
    if (it == user_sessions_by_ip_.end())
    {
      return UserSessionPtr();
    }

    return it->second;
  }
}
