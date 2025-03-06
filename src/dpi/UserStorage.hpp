#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "Logger.hpp"


namespace dpi
{
  class UserStorage
  {
  public:
    struct User
    {
      std::string msisdn;
      uint32_t ip;

      std::string to_string() const;
    };

    using UserPtr = std::shared_ptr<User>;

  public:
    UserStorage(LoggerPtr event_logger);

    void set_event_logger(LoggerPtr event_logger);

    void add_user(std::string_view msisdn, uint32_t ip);

    void remove_user(std::string_view msisdn);

    UserPtr get_user_by_ip(uint32_t ip) const;

  private:
    void remove_user_i_(const std::string& msisdn);

    void add_user_i_(UserPtr new_user);

    void log_event_(const std::string& msg);

  private:
    LoggerPtr event_logger_;
    mutable std::shared_mutex lock_;
    std::unordered_map<uint32_t, UserPtr> users_by_ip_;
    std::unordered_map<std::string, UserPtr> users_by_msisdn_;
  };

  using UserStoragePtr = std::shared_ptr<UserStorage>;
}
