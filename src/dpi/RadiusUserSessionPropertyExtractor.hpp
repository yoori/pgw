#pragma once

#include <list>
#include <unordered_map>

#include <radproto/dictionaries.h>
#include <radproto/packet.h>

#include "Attribute.hpp"
#include "UserSessionPropertyContainer.hpp"

namespace dpi
{
  class RadiusUserSessionPropertyExtractor
  {
  public:
    RadiusUserSessionPropertyExtractor(
      const std::string& dictionary_path,
      const std::string& secret,
      const std::list<std::pair<ConstAttributeKeyPtr, std::string>>& parse_attributes,
      const std::unordered_map<std::string, dpi::Value>& global_properties);

    UserSessionPropertyContainerPtr
    extract(const RadProto::Packet& request) const;

  private:
    using RadiusAttributeParseMap = std::unordered_map<
      ConstAttributeKeyPtr,
      std::list<std::string>, //< name of properties for push
      AttributeKeyPtrHash,
      AttributeKeyPtrEqual
    >;

  private:
    RadProto::Dictionaries dictionaries_;
    const std::string secret_;
    RadiusAttributeParseMap extract_attributes_;
    std::unordered_map<std::string, dpi::Value> global_properties_;
  };

  using RadiusUserSessionPropertyExtractorPtr =
    std::shared_ptr<RadiusUserSessionPropertyExtractor>;
}

