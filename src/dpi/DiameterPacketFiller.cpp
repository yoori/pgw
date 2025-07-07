#include <limits>

#include "DiameterPacketFiller.hpp"

namespace dpi
{
  namespace
  {
    Diameter::AVP::Data
    fill_string_avp_data(const std::string& value)
    {
      return Diameter::AVP::Data().setOctetString(ByteArray::fromASCII(value.c_str()));
    }

    Diameter::AVP::Data
    fill_octets_avp_data(const ByteArrayValue& value)
    {
      return Diameter::AVP::Data().setOctetString(ByteArray(&value[0], value.size()));
    }

    Diameter::AVP::Data
    fill_octets_avp_data(const uint8_t* buf, int size)
    {
      return Diameter::AVP::Data().setOctetString(ByteArray(buf, size));
    }

    Diameter::AVP::Data
    fill_uint32_avp_data(uint32_t value)
    {
      return Diameter::AVP::Data().setUnsigned32(value);
    }

    Diameter::AVP::Data
    fill_uint64_avp_data(uint32_t value)
    {
      return Diameter::AVP::Data().setUnsigned64(value);
    }

    Diameter::AVP::Data
    fill_int32_avp_data(uint32_t value)
    {
      return Diameter::AVP::Data().setInteger32(value);
    }

    Diameter::AVP::Data
    fill_int64_avp_data(uint32_t value)
    {
      return Diameter::AVP::Data().setInteger64(value);
    }

    Diameter::AVP::Data
    fill_float32_avp_data(uint32_t value)
    {
      return Diameter::AVP::Data().setInteger32(value);
    }

    class AVPFillVisitor
    {
    public:
      AVPFillVisitor(
        Diameter::AVP::Data& avp_data,
        const DiameterDictionary::AVP& avp_dict)
        : avp_data_(avp_data),
          avp_dict_(avp_dict)
      {}

      void
      operator()(uint64_t val)
      {
        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_UNSIGNED32)
        {
          if (val > std::numeric_limits<uint32_t>::max())
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill uint32 by value: ") + std::to_string(val));
          }

          avp_data_ = fill_uint32_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_UNSIGNED64)
        {
          avp_data_ = fill_uint32_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_INTEGER32)
        {
          if (val > std::numeric_limits<int32_t>::max())
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill int32 by value: ") + std::to_string(val));
          }

          avp_data_ = fill_int32_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_INTEGER64)
        {
          if (val > std::numeric_limits<int64_t>::max())
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill int64 by value: ") + std::to_string(val));
          }

          avp_data_ = fill_int64_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_OCTETSTRING &&
          avp_dict_.custom_type == "Address")
        {
          if (val > std::numeric_limits<uint32_t>::max())
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill address by value: ") + std::to_string(val));
          }

          const uint8_t addr_buf[] = {
            0,
            0x1,
            static_cast<uint8_t>(val & 0xFF),
            static_cast<uint8_t>((val >> 8) & 0xFF),
            static_cast<uint8_t>((val >> 16) & 0xFF),
            static_cast<uint8_t>((val >> 24) & 0xFF)
          };
          avp_data_ = fill_octets_avp_data(addr_buf, sizeof(addr_buf));
          return;
        }

        throw DiameterPacketFiller::IncompatibleType(
          std::string("Can't fill ") +
          DiameterDictionary::avp_value_type_to_string(avp_dict_.base_type) +
          "(" + avp_dict_.name + ":" + std::to_string(avp_dict_.avp_code) +
          ") by uint");
      }

      void
      operator()(int64_t val)
      {
        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_UNSIGNED32)
        {
          if (val < 0 || val > std::numeric_limits<uint32_t>::max())
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill uint32 by value: ") + std::to_string(val));
          }

          avp_data_ = fill_uint32_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_UNSIGNED64)
        {
          if (val < 0)
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill uint64 by value: ") + std::to_string(val));
          }

          avp_data_ = fill_uint32_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_INTEGER32)
        {
          if (val < std::numeric_limits<int32_t>::min() || val > std::numeric_limits<int32_t>::max())
          {
            throw DiameterPacketFiller::IncompatibleType(
              std::string("Can't fill int32 by value: ") + std::to_string(val));
          }

          avp_data_ = fill_int32_avp_data(val);
          return;
        }

        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_INTEGER64)
        {
          avp_data_ = fill_int64_avp_data(val);
          return;
        }

        throw DiameterPacketFiller::IncompatibleType(
          std::string("Can't fill ") +
          DiameterDictionary::avp_value_type_to_string(avp_dict_.base_type) + " by int64");
      }

      void
      operator()(const std::string& val)
      {
        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_OCTETSTRING)
        {
          avp_data_ = fill_string_avp_data(val);
          return;
        }

        throw DiameterPacketFiller::IncompatibleType(
          std::string("Can't fill ") +
          DiameterDictionary::avp_value_type_to_string(avp_dict_.base_type) + " by string");
      }

      void
      operator()(const ByteArrayValue& val)
      {
        if (avp_dict_.base_type == DiameterDictionary::AVPValueType::AVP_TYPE_OCTETSTRING)
        {
          avp_data_ = fill_octets_avp_data(val);
          return;
        }

        throw DiameterPacketFiller::IncompatibleType(
          std::string("Can't fill ") +
          DiameterDictionary::avp_value_type_to_string(avp_dict_.base_type) + " by octets");
      }

    private:
      Diameter::AVP::Data& avp_data_;
      const DiameterDictionary::AVP& avp_dict_;
    };

    class AVPNonEmptyVisitor
    {
    public:
      AVPNonEmptyVisitor(bool& non_empty)
        : non_empty_(non_empty)
      {}

      void
      operator()(uint64_t)
      {
        non_empty_ = true;
      }

      void
      operator()(int64_t)
      {
        non_empty_ = true;
      }

      void
      operator()(const std::string& val)
      {
        non_empty_ = !val.empty();
      }

      void
      operator()(const ByteArrayValue& val)
      {
        non_empty_ = !val.empty();
      }

    private:
      bool& non_empty_;
    };
  };

  DiameterPacketFiller::DiameterPacketFiller(
    const DiameterDictionary& diameter_dictionary,
    unsigned int request_code)
    : diameter_dictionary_(diameter_dictionary),
      request_code_(request_code),
      root_node_(std::make_shared<AVPNode>())
  {}

  void
  DiameterPacketFiller::add_non_empty_avp(const std::string& path, const Value& value)
  {
    bool non_empty = true;
    std::visit(AVPNonEmptyVisitor(non_empty), value);
    if (non_empty)
    {
      std::cout << "DiameterPacketFiller::add_non_empty_avp: ADD NON EMPTY " << path << std::endl;
      add_avp(path, value);
    }
  }

  void
  DiameterPacketFiller::add_avp(const std::string& path, const Value& value)
  {
    std::optional<DiameterDictionary::AVPPath> avp_path = diameter_dictionary_.get_request_avp_path(
      request_code_,
      path);

    if (avp_path.has_value())
    {
      auto last_it = avp_path->avps.end();
      --last_it;

      AVPNode* cur_avp_node = root_node_.get();

      for (auto avp_it = avp_path->avps.begin(); avp_it != last_it; ++avp_it)
      {
        auto avp_node_it = cur_avp_node->child_avps.find((*avp_it)->avp_code);
        if (avp_node_it == cur_avp_node->child_avps.end())
        {
          // add to packet
          //.addAVP(create_string_avp(263, request_key.session_id, std::nullopt, true))
          auto ins = cur_avp_node->child_avps.emplace(
            (*avp_it)->avp_code,
            std::make_shared<AVPNode>());
          cur_avp_node = ins.first->second.get();
          cur_avp_node->avp_dict = *avp_it;
        }
        else
        {
          cur_avp_node = avp_node_it->second.get();
        }
      }

      auto avp_node = std::make_shared<AVPNode>();
      avp_node->avp_dict = *last_it;
      avp_node->avp_data = create_avp_data_(value, **last_it);
      cur_avp_node->child_avps.emplace((*last_it)->avp_code, avp_node);
    }
    else
    {
      throw NoAVP(std::string("Can't find AVP by path: ") + path);
    }
  }

  void
  DiameterPacketFiller::apply(Diameter::Packet& packet)
  {
    //std::cout << "DiameterPacketFiller::apply(): " << root_node_->child_avps.size() << std::endl;
    for (const auto& [avp_code, avp_node] : root_node_->child_avps)
    {
      //std::cout << "DiameterPacketFiller::apply(): AVP = " << avp_node->avp_dict->name << std::endl;
      Diameter::AVP::Data avp_data;
      apply_to_(avp_data, *avp_node);
      packet.addAVP(create_avp_(*(avp_node->avp_dict), avp_data));
    }
  }

  void
  DiameterPacketFiller::apply_to_(Diameter::AVP::Data& avp_data, const AVPNode& avp_node)
  {
    if (!avp_node.child_avps.empty())
    {
      for (const auto& [internal_avp_code, internal_avp_node] : avp_node.child_avps)
      {
        Diameter::AVP::Data internal_avp_data;
        apply_to_(internal_avp_data, *internal_avp_node);
        avp_data.addAVP(create_avp_(*internal_avp_node->avp_dict, internal_avp_data));
      }
    }
    else
    {
      avp_data = avp_node.avp_data;
    }
  }

  Diameter::AVP
  DiameterPacketFiller::create_avp_(
    const DiameterDictionary::AVP& avp,
    const Diameter::AVP::Data& avp_data)
  {
    auto header = Diameter::AVP::Header()
      .setAVPCode(avp.avp_code)
      .setFlags(Diameter::AVP::Header::Flags(avp.flags))
    ;

    if (avp.vendor_id != 0)
    {
      header.setVendorID(avp.vendor_id);
    }

    return Diameter::AVP()
      .setHeader(header)
      .setData(avp_data)
      // Updating AVP length field, according to header and data value.
      .updateLength();
  }

  Diameter::AVP
  DiameterPacketFiller::create_avp_(
    const DiameterDictionary::AVP& avp,
    const Value& value)
  {
    return create_avp_(avp, create_avp_data_(value, avp));
  }

  Diameter::AVP::Data
  DiameterPacketFiller::create_avp_data_(
    const Value& value,
    const DiameterDictionary::AVP& avp_dict)
  {
    Diameter::AVP::Data avp_data;
    AVPFillVisitor avp_fill_visitor(avp_data, avp_dict);
    std::visit(avp_fill_visitor, value);
    return avp_data;
  }
}
