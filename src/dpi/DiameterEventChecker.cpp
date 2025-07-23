#include "DiameterEventChecker.hpp"

namespace dpi
{
  namespace
  {
    std::optional<Value>
    get_value(
      const UserSessionPropertyContainerPtr& container,
      const std::string& property_name)
    {
      auto val_it = container->values.find(property_name);
      if (val_it == container->values.end())
      {
        return std::nullopt;
      }

      return val_it->second;
    }
  };

  bool
  DiameterEventChecker::compare_user_location_info_(
    std::vector<EventTrigger>& res,
    const Value& old_value,
    const Value& new_value)
  {
    if (!std::holds_alternative<ByteArrayValue>(old_value) ||
      !std::holds_alternative<ByteArrayValue>(new_value))
    {
      return false;
    }

    const ByteArrayValue& old_value_ba = std::get<ByteArrayValue>(old_value);
    const ByteArrayValue& new_value_ba = std::get<ByteArrayValue>(new_value);

    if (old_value_ba.empty() || new_value_ba.empty())
    {
      return false;
    }

    if (old_value_ba[0] != 130 || //< TAI and ECGI type
      new_value_ba[0] != 130 ||
      old_value_ba.size() != 13 || //< 1(type) + 5(TAI) + 7(ECGI) = 13
      new_value_ba.size() != 13
      )
    {
      return false;
    }

    if (!std::equal(
      old_value_ba.begin() + 1,
      old_value_ba.begin() + 6,
      new_value_ba.begin() + 1))
    {
      res.emplace_back(EventTrigger::TAI_CHANGE);
    }

    if (!std::equal(
      old_value_ba.begin() + 6,
      old_value_ba.end(),
      new_value_ba.begin() + 6))
    {
      res.emplace_back(EventTrigger::ECGI_CHANGE);
    }

    return true;
  }

  std::vector<EventTrigger>
  DiameterEventChecker::check(
    const UserSessionPropertyContainerPtr& old_user_session_property_container,
    const UserSessionPropertyContainerPtr& new_user_session_property_container)
    const
  {
    if (!old_user_session_property_container || !new_user_session_property_container)
    {
      return std::vector<EventTrigger>();
    }
    
    std::vector<EventTrigger> res;

    std::optional<Value> old_rat_type = get_value(old_user_session_property_container, "RAT-Type");
    std::optional<Value> new_rat_type = get_value(new_user_session_property_container, "RAT-Type");

    if (old_rat_type != new_rat_type)
    {
      res.emplace_back(EventTrigger::RAT_CHANGE);
    }
    
    std::optional<Value> old_user_location = get_value(old_user_session_property_container, "User-Location-Info");
    std::optional<Value> new_user_location = get_value(new_user_session_property_container, "User-Location-Info");

    if (new_user_location.has_value())
    {
      if (std::holds_alternative<std::string>(*new_user_location))
      {
        std::cout << "XXX User-Location-Info is string" << std::endl;
      }
      else if (std::holds_alternative<ByteArrayValue>(*new_user_location))
      {
        std::cout << "XXX User-Location-Info is ByteArrayValue" << std::endl;
      }
      else
      {
        std::cout << "XXX User-Location-Info is other" << std::endl;
      }
    }

    if (old_user_location != new_user_location)
    {
      res.emplace_back(EventTrigger::USER_LOCATION_CHANGE);

      if (!old_user_location.has_value() ||
        !new_user_location.has_value() ||
        !compare_user_location_info_(res, *old_user_location, *new_user_location))
      {
        res.emplace_back(EventTrigger::TAI_CHANGE);
        res.emplace_back(EventTrigger::ECGI_CHANGE);
      }
    }

    std::optional<Value> old_sgsn_address = get_value(old_user_session_property_container, "SGSN-Address");
    std::optional<Value> new_sgsn_address = get_value(new_user_session_property_container, "SGSN-Address");

    if (old_sgsn_address != new_sgsn_address)
    {
      res.emplace_back(EventTrigger::AN_GW_CHANGE);
    }

    std::optional<Value> old_framed_ip_address = get_value(old_user_session_property_container, "Framed-IP-Address");
    std::optional<Value> new_framed_ip_address = get_value(new_user_session_property_container, "Framed-IP-Address");

    if (old_framed_ip_address != new_framed_ip_address)
    {
      res.emplace_back(EventTrigger::UE_IP_ADDRESS_ALLOCATE);
    }

    return res;
  }
}
