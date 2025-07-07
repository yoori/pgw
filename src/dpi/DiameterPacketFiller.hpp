#pragma once

#include  <unordered_map>

#include <Diameter/Packet.hpp>

#include "DiameterDictionary.hpp"
#include "Value.hpp"

namespace dpi
{
  class DiameterPacketFiller
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(IncompatibleType, Exception);
    DECLARE_EXCEPTION(NoAVP, Exception);

  public:
    DiameterPacketFiller(const DiameterDictionary& diameter_dictionary, unsigned int request_code);

    void
    add_avp(const std::string& path, const Value& value);

    void
    add_non_empty_avp(const std::string& path, const Value& value);

    void
    apply(Diameter::Packet& packet);

  private:
    struct AVPNode
    {
      AVPNode()
      {}

      DiameterDictionary::ConstAVPPtr avp_dict;
      std::unordered_map<unsigned long, std::shared_ptr<AVPNode>> child_avps;
      Diameter::AVP::Data avp_data; //< fill only for basic types
    };

    using AVPNodePtr = std::shared_ptr<AVPNode>;
    //using AVPNodeMap = std::unordered_map<unsigned long, AVPNodePtr>;

  private:
    void
    apply_to_(Diameter::AVP::Data& avp_data, const AVPNode& avp_node);

    static Diameter::AVP
    create_avp_(
      const DiameterDictionary::AVP& avp,
      const Diameter::AVP::Data& avp_data);

    static Diameter::AVP
    create_avp_(
      const DiameterDictionary::AVP& avp,
      const Value& value);

    static Diameter::AVP::Data
    create_avp_data_(
      const Value& value,
      const DiameterDictionary::AVP& avp_dict);

  private:
    const DiameterDictionary& diameter_dictionary_;
    const unsigned int request_code_;
    AVPNodePtr root_node_;
  };
}
