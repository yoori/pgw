#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include <memory>

#include "NetworkUtils.hpp"
#include "UserSessionPropertyContainer.hpp"

namespace dpi
{
  // Session linked to user
  struct UserSessionTraits
  {
    uint32_t framed_ip_address = 0;
    std::string msisdn;

    UserSessionPropertyContainerPtr user_session_property_container;

    bool
    operator==(const UserSessionTraits& right) const;

    std::string to_string() const;
  };

  using ConstUserSessionTraitsPtr = std::shared_ptr<const UserSessionTraits>;
}

namespace dpi
{
  inline bool
  UserSessionTraits::operator==(const UserSessionTraits& right) const
  {
    return framed_ip_address == right.framed_ip_address &&
      msisdn == right.msisdn;
  }

  inline std::string
  UserSessionTraits::to_string() const
  {
    return std::string("{") +
      "\"framed_ip_address\": \"" + ipv4_address_to_string(framed_ip_address) + "\"," +
      "\"msisdn\": \"" + msisdn + "\"," +
      "\"user_session_property_container\": " + (
        user_session_property_container ? user_session_property_container->to_string() : std::string("{}")) +
      "}";
  }
}
