#include <radproto/packet_reader.h>

#include "Value.hpp"

#include "RadiusUserSessionPropertyExtractor.hpp"

namespace dpi
{
  RadiusUserSessionPropertyExtractor::RadiusUserSessionPropertyExtractor(
    const std::string& dictionary_path,
    const std::string& secret,
    const std::list<std::pair<ConstAttributeKeyPtr, std::string>>& extract_attributes)
    : dictionaries_(dictionary_path),
      secret_(secret)
  {
    dictionaries_.resolve();

    for (const auto& [attr, property_name] : extract_attributes)
    {
      extract_attributes_[attr].emplace_back(property_name);
    }
  }

  Value attr_to_value(RadProto::ConstAttributePtr attr)
  {
    auto uint_var = attr->as_uint();
    if (uint_var.has_value())
    {
      return dpi::Value(std::in_place_type<uint64_t>, *uint_var);
    }

    auto int_var = attr->as_int();
    if (int_var.has_value())
    {
      return dpi::Value(std::in_place_type<int64_t>, *int_var);
    }

    auto str_var = attr->as_string();
    if (str_var.has_value())
    {
      return dpi::Value(*str_var);
    }

    RadProto::ByteArray octets = attr->as_octets();
    return ByteArrayValue(octets.begin(), octets.end());
  }
  
  UserSessionPropertyContainerPtr
  RadiusUserSessionPropertyExtractor::extract(const RadProto::Packet& request) const
  {
    UserSessionPropertyContainerPtr result_property_container =
      std::make_shared<UserSessionPropertyContainer>();
    RadProto::PacketReader packet_reader(request, dictionaries_, secret_);

    for (const auto& [extract_attribute, property_names] : extract_attributes_)
    {
      RadProto::ConstAttributePtr parsed_attribute;

      if (extract_attribute->vendor.empty())
      {
        parsed_attribute = packet_reader.get_attribute_by_name(
          extract_attribute->name);
      }
      else
      {
        parsed_attribute = packet_reader.get_attribute_by_name(
          extract_attribute->name,
          extract_attribute->vendor);
      }

      if (parsed_attribute)
      {
        for (const auto& property_name : property_names)
        {
          Value result_value = attr_to_value(parsed_attribute);
          result_property_container->values.emplace(property_name, result_value);
        }
      }
    }

    return result_property_container;
  }
}
