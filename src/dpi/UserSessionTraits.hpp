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
    std::string radius_session_id;

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
      msisdn == right.msisdn &&
      radius_session_id == right.radius_session_id;
  }

  inline std::string
  UserSessionTraits::to_string() const
  {
    return std::string("{") +
      "\"framed_ip_address\": \"" + ipv4_address_to_string(framed_ip_address) + "\"," +
      "\"msisdn\": \"" + msisdn + "\"," +
      "\"radius_session_id\": \"" + radius_session_id + "\"," +
      "\"user_session_property_container\": " + (
        user_session_property_container ? user_session_property_container->to_string() : std::string("{}")) +
      "}";
  }
}
