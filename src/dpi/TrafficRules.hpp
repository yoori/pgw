#pragma once

#include <optional>

#include <gears/HashTable.hpp>

#include "SessionKey.hpp"

namespace dpi
{
  // traffic_type => mk, rg
  struct DiameterTrafficType
  {
    DiameterTrafficType() {}

    DiameterTrafficType(
      std::optional<unsigned long> rating_group_val,
      std::optional<unsigned long> monitoring_key_val)
      : rating_group(std::move(rating_group_val)),
        monitoring_key(std::move(monitoring_key_val))
    {}

    std::optional<unsigned long> rating_group;
    std::optional<unsigned long> monitoring_key;
  };

  class DiameterTrafficTypeProvider
  {
  public:
    using DiameterTrafficTypeArray = std::vector<DiameterTrafficType>;

  public:
    DiameterTrafficTypeProvider();

    const DiameterTrafficTypeArray&
    get_diameter_traffic_type(const SessionKey& session_key) const;

  private:
    DiameterTrafficTypeArray default_traffic_types_;
    Gears::HashTable<SessionKey, DiameterTrafficTypeArray> diameter_traffic_type_by_session_key_;
  };
}
