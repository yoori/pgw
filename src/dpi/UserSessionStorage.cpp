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
      std::cout << "User sessions: add session for ip = " <<
        ipv4_address_to_string(user_session_traits.framed_ip_address) <<
        " (msisdn = " << user->msisdn() << ")" <<
        std::endl;

      std::unique_lock lock{lock_};

      auto it = user_sessions_by_ip_.find(user_session_traits.framed_ip_address);
      if (it != user_sessions_by_ip_.end())
      {
        added_session = it->second;
      }
      else
      {
        added_session = std::make_shared<UserSession>(user_session_traits, user);
        user_sessions_by_ip_.emplace(
          user_session_traits.framed_ip_address,
          added_session);
        user_sessions_by_gx_session_suffix_.emplace(
          added_session->gx_session_suffix(),
          added_session);
      }
    }

    return added_session;
  }

  UserSessionPtr
  UserSessionStorage::remove_user_session(uint32_t ip)
  {
    std::cout << "User sessions: remove session for ip = " <<
      ipv4_address_to_string(ip) <<
      std::endl;
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

  UserSessionPtr
  UserSessionStorage::get_user_session_by_gx_session_suffix(const std::string& gx_session_suffix) const
  {
    std::shared_lock lock{lock_};

    auto it = user_sessions_by_gx_session_suffix_.find(gx_session_suffix);
    if (it == user_sessions_by_gx_session_suffix_.end())
    {
      return UserSessionPtr();
    }

    return it->second;
  }
}
