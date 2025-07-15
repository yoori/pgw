#pragma once

#include <string>
#include <gears/Hash.hpp>

namespace dpi
{
  struct SessionKey
  {
    SessionKey();

    SessionKey(std::string traffic_type, std::string category_type);

    SessionKey& operator=(const SessionKey& init);

    bool operator==(const SessionKey& right) const;

    unsigned long hash() const;

    const std::string& traffic_type() const;

    const std::string& category_type() const;

    std::string to_string() const;

  protected:
    void calc_hash_();

  protected:
    std::string traffic_type_;
    std::string category_type_;
    unsigned long hash_;
  };

  using SessionKeyArray = std::vector<SessionKey>;
}

namespace dpi
{
  inline
  SessionKey::SessionKey()
    : hash_(0)
  {}

  inline
  SessionKey::SessionKey(std::string traffic_type_val, std::string category_type_val)
    : traffic_type_(std::move(traffic_type_val)),
      category_type_(std::move(category_type_val)),
      hash_(0)
  {
    calc_hash_();
  }

  inline
  bool SessionKey::operator==(const SessionKey& right) const
  {
    return traffic_type_ == right.traffic_type_ &&
      category_type_ == right.category_type_;
  }

  inline unsigned long
  SessionKey::hash() const
  {
    return hash_;
  }

  inline const std::string&
  SessionKey::traffic_type() const
  {
    return traffic_type_;
  }

  inline const std::string&
  SessionKey::category_type() const
  {
    return category_type_;
  }

  inline void
  SessionKey::calc_hash_()
  {
    Gears::Murmur64Hash hasher(hash_);
    hash_add(hasher, traffic_type_);
    hash_add(hasher, category_type_);
  }

  inline SessionKey&
  SessionKey::operator=(const SessionKey& init)
  {
    traffic_type_ = init.traffic_type_;
    category_type_ = init.category_type_;
    hash_ = init.hash_;
    return *this;
  }

  inline std::string
  SessionKey::to_string() const
  {
    return std::string("{traffic_type = ") + traffic_type_ +
      ", category_type = " + category_type_ + "}";
  }
}
