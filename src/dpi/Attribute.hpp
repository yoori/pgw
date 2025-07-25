#pragma once

#include <string>
#include <unordered_set>
#include <boost/functional/hash.hpp>

namespace dpi
{
  struct AttributeKey
  {
    AttributeKey();

    AttributeKey(const std::string& name, const std::string& vendor);

    std::string name;
    std::string vendor;

    bool operator==(const AttributeKey& right) const;
  };

  using ConstAttributeKeyPtr = std::shared_ptr<const AttributeKey>;

  struct AttributeKeyPtrEqual
  {
    bool operator()(
      const ConstAttributeKeyPtr& left,
      const ConstAttributeKeyPtr& right) const
    {
      return left == right || (
        left->name == right->name && left->vendor == right->vendor);
    }
  };

  struct AttributeKeyPtrHash
  {
    std::size_t
    operator()(const ConstAttributeKeyPtr& attribute_key) const
    {
      std::size_t seed = 0;
      boost::hash_combine(seed, attribute_key->name);
      boost::hash_combine(seed, attribute_key->vendor);
      return seed;
    }
  };

  using ConstAttributeKeyPtrSet = std::unordered_set<
    ConstAttributeKeyPtr,
    AttributeKeyPtrHash,
    AttributeKeyPtrEqual>;
}

namespace dpi
{
  // AttributeKey impl
  inline
  AttributeKey::AttributeKey()
  {}

  inline
  AttributeKey::AttributeKey(const std::string& name_val, const std::string& vendor_val)
    : name(name_val),
      vendor(vendor_val)
  {}

  inline bool
  AttributeKey::operator==(const AttributeKey& right) const
  {
    return name == right.name && vendor == right.vendor;
  }
}
