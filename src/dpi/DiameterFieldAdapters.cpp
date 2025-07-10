#include <limits>
#include <unordered_map>

#include "NetworkUtils.hpp"
#include "DiameterFieldAdapters.hpp"
#include "DiameterPacketFiller.hpp"

namespace dpi
{
  namespace
  {
    class IPv4As4BytesFillVisitor
    {
    public:
      IPv4As4BytesFillVisitor(Value& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        result_ = int_to_buf_(string_to_ipv4_address(val));
      }

      void
      operator()(int64_t val)
      {
        if (val < 0 || val > std::numeric_limits<uint32_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill ipv4 as 4 bytes by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(uint64_t val)
      {
        if (val > std::numeric_limits<uint32_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill ipv4 as 4 bytes by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = val;
      }

    private:
      Value int_to_buf_(uint32_t val)
      {
        const uint8_t addr_buf[] = {
          static_cast<uint8_t>(val & 0xFF),
          static_cast<uint8_t>((val >> 8) & 0xFF),
          static_cast<uint8_t>((val >> 16) & 0xFF),
          static_cast<uint8_t>((val >> 24) & 0xFF)
        };

        return Value(ByteArrayValue(addr_buf, addr_buf + sizeof(addr_buf)));
      }

    private:
      Value& result_;
    };

    class TimezoneAs2BytesFillVisitor
    {
    public:
      TimezoneAs2BytesFillVisitor(Value& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        try
        {
          result_ = int_to_buf_(std::stoi(val));
        }
        catch (const std::invalid_argument&)
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill timezone 2 bytes by value: ") + val);
        }
      }

      void
      operator()(int64_t val)
      {
        if (val < 0 || val > std::numeric_limits<uint8_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill timezone 2 bytes by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(uint64_t val)
      {
        if (val > std::numeric_limits<uint8_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill timezone 2 bytes by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = val;
      }

    private:
      Value int_to_buf_(uint8_t val)
      {
        const uint8_t buf[] = { val, 0 };
        return Value(ByteArrayValue(buf, buf + sizeof(buf)));
      }

    private:
      Value& result_;
    };

    class IntAs4BytesFillVisitor
    {
    public:
      IntAs4BytesFillVisitor(Value& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        try
        {
          result_ = int_to_buf_(std::stoi(val));
        }
        catch (const std::invalid_argument&)
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill 4 bytes by value: ") + val);
        }
      }

      void
      operator()(int64_t val)
      {
        if (val < 0 || val > std::numeric_limits<uint32_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill 4 bytes by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(uint64_t val)
      {
        if (val > std::numeric_limits<uint32_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill 4 bytes by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = val;
      }

    private:
      Value int_to_buf_(uint32_t val)
      {
        const uint8_t buf[] = {
          static_cast<uint8_t>((val >> 24) & 0xFF),
          static_cast<uint8_t>((val >> 16) & 0xFF),
          static_cast<uint8_t>((val >> 8) & 0xFF),
          static_cast<uint8_t>(val & 0xFF)
        };
        return Value(ByteArrayValue(buf, buf + sizeof(buf)));
      }

    private:
      Value& result_;
    };

    class IntAsByteFillVisitor
    {
    public:
      IntAsByteFillVisitor(Value& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        try
        {
          result_ = int_to_buf_(std::stoi(val));
        }
        catch (const std::invalid_argument&)
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill byte by value: ") + val);
        }
      }

      void
      operator()(int64_t val)
      {
        if (val < 0 || val > std::numeric_limits<uint8_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill byte by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(uint64_t val)
      {
        if (val > std::numeric_limits<uint8_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill byte by value: ") + std::to_string(val));
        }

        result_ = int_to_buf_(val);
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = val;
      }

    private:
      Value int_to_buf_(uint8_t val)
      {
        const uint8_t buf[] = {
          static_cast<uint8_t>(val & 0xFF)
        };
        return Value(ByteArrayValue(buf, buf + sizeof(buf)));
      }

    private:
      Value& result_;
    };

    class ToStringFillVisitor
    {
    public:
      ToStringFillVisitor(Value& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        result_ = val;
      }

      void
      operator()(int64_t val)
      {
        result_ = std::to_string(val);
      }

      void
      operator()(uint64_t val)
      {
        result_ = std::to_string(val);
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = std::string(reinterpret_cast<const char*>(&val[0]), val.size());
      }

    private:
      Value& result_;
    };
  };

  struct DefaultDiameterFieldAdapter: public DiameterFieldAdapter
  {
    Value adapt(const Value& value) const override
    {
      return value;
    }
  };

  class IPv4As4BytesDiameterFieldAdapter: public DiameterFieldAdapter
  {
  public:
    virtual Value adapt(const Value& value) const
    {
      std::cout << "IPv4As4BytesDiameterFieldAdapter::adapt" << std::endl;

      Value result;
      IPv4As4BytesFillVisitor visitor(result);
      std::visit(visitor, value);
      return result;
    }
  };

  class IntAs4BytesDiameterFieldAdapter: public DiameterFieldAdapter
  {
  public:
    virtual Value adapt(const Value& value) const
    {
      Value result;
      IntAs4BytesFillVisitor visitor(result);
      std::visit(visitor, value);
      return result;
    }
  };

  class IntAsByteDiameterFieldAdapter: public DiameterFieldAdapter
  {
  public:
    virtual Value adapt(const Value& value) const
    {
      Value result;
      IntAsByteFillVisitor visitor(result);
      std::visit(visitor, value);
      return result;
    }
  };

  class TimezoneAs2BytesDiameterFieldAdapter: public DiameterFieldAdapter
  {
  public:
    virtual Value adapt(const Value& value) const
    {
      Value result;
      TimezoneAs2BytesFillVisitor visitor(result);
      std::visit(visitor, value);
      return result;
    }
  };

  class ToStringDiameterFieldAdapter: public DiameterFieldAdapter
  {
  public:
    virtual Value adapt(const Value& value) const
    {
      Value result;
      ToStringFillVisitor visitor(result);
      std::visit(visitor, value);
      return result;
    }
  };

  DiameterFieldAdapterDictionary::DiameterFieldAdapterDictionary()
    : default_adapter_(std::make_shared<DefaultDiameterFieldAdapter>())
  {
    adapters_.emplace("ipv4-as-4bytes", std::make_shared<IPv4As4BytesDiameterFieldAdapter>());
    adapters_.emplace("timezone-as-2bytes", std::make_shared<TimezoneAs2BytesDiameterFieldAdapter>());
    adapters_.emplace("int-as-4bytes", std::make_shared<IntAs4BytesDiameterFieldAdapter>());
    adapters_.emplace("int-as-1byte", std::make_shared<IntAsByteDiameterFieldAdapter>());
    adapters_.emplace("to-string", std::make_shared<ToStringDiameterFieldAdapter>());
  }

  DiameterFieldAdapterPtr
  DiameterFieldAdapterDictionary::get_adapter(const std::string& name)
  {
    auto it = adapters_.find(name);
    if (it != adapters_.end())
    {
      return it->second;
    }

    return default_adapter_;
  }

  DiameterFieldAdapterDictionary&
  DiameterFieldAdapterDictionary::instance()
  {
    static DiameterFieldAdapterDictionary inst;
    return inst;
  }
}
