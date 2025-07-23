#pragma once

#include <vector>

#include "Types.hpp"
#include "UserSessionPropertyContainer.hpp"

namespace dpi
{
  class DiameterEventChecker
  {
  public:
    EventTriggerArray
    check(const UserSessionPropertyContainerPtr& old_user_session_property_container,
      const UserSessionPropertyContainerPtr& new_user_session_property_container)
      const;

  private:
    static bool
    compare_user_location_info_(
      std::vector<EventTrigger>& res,
      const Value& old_value,
      const Value& new_value);
  };
}
