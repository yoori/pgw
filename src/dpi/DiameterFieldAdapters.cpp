#include <limits>
#include <unordered_map>

#include "NetworkUtils.hpp"
#include "DiameterFieldAdapters.hpp"
#include "DiameterPacketFiller.hpp"

namespace dpi
{
  namespace
  {
    // IPv4As4BytesFillVisitor
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

    // TimezoneAs2BytesFillVisitor
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

    // IntAs4BytesFillVisitor
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

    // IntAsByteFillVisitor
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

    // ToStringFillVisitor
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

    class RadiusRATTypeToDiameterRATTypeConverter
    {
    public:
      /*
        Diameter RAT-Type

           0 - WLAN
           1 - Virtual (indicates that RAT is unknown)
        1000 — Universal Terrestrial Radio Access Network (UTRAN)
        1001 — GSM Edge Radio Access Network (GERAN)
        1002 - GAN (Generic Access Network)
        1003 - HSPA_EVOLUTION (Evolved High Speed Packet Access)
        1004 — Evolved UMTS Radio Access Network (EUTRAN)
        1007 - LTR-M

        2000 - CDMA2000_1X (core CDMA2000 wireless air interface)
        2001 - HRPD (High Rate Packet Data)
        2002 - UMB (Ultra Mobile Broadband)
        2003 - EHRPD (Enhanced High Rate Packet Data)

        3GPP-RAT-Type (radius RAT-Type)

        VALUE	RAT-Type			UTRAN			1
        VALUE	RAT-Type			GERAN			2
        VALUE	RAT-Type			WLAN			3
        VALUE	RAT-Type			GAN			4
        VALUE	RAT-Type			HSPA-Evolution		5

        VALUE	RAT-Type			EUTRAN			6
        VALUE	RAT-Type			Virtual			7
        VALUE	RAT-Type			EUTRAN-NB-IoT		8
        VALUE	RAT-Type			LTE-M			9

        # 10+ Specified in 3GPP TS 29.061
        VALUE	RAT-Type			NR			51
        VALUE	RAT-Type			NR-Unlicensed		52
        VALUE	RAT-Type			Trusted-WLAN		53
        VALUE	RAT-Type			Trusted-Non-3GPP	54

        VALUE	RAT-Type			Wireline-Access		55
        VALUE	RAT-Type			Wireline-Cable-Access	56
        VALUE	RAT-Type			Wireline-BPF-Access	57
        VALUE	RAT-Type			IEEE-802.16e		101
        VALUE	RAT-Type			3GPP2-eHRPD		102
        VALUE	RAT-Type			3GPP2-HRPD		103
        VALUE	RAT-Type			3GPP2-1xRTT		104
        VALUE	RAT-Type			3GPP2-UMB		105
      */
      RadiusRATTypeToDiameterRATTypeConverter()
        : replace_values_{
          { 1, 1000 }, // UTRAN => UTRAN
          { 2, 1001 }, // GERAN => GERAN
          { 3, 0 }, // WLAN => WLAN
          { 4, 1002 }, // GAN => GAN
          { 5, 1003 }, // HSPA-Evolution => HSPA-Evolution
          { 6, 1004 }, // EUTRAN => EUTRAN
          { 7, 1 }, // Virtual => Virtual
          { 8, 1004}, // EUTRAN-NB-IoT => EUTRAN
          { 9, 1007}, // LTE-M => LTE-M (https://www.cisco.com/c/en/us/td/docs/wireless/upc/21-27/cups-up-admin/21-27-upc-cups-up-admin-guide/m_lte-m-rat-type-support.pdf)

          { 51, 1 }, // 51 : NR ?
          { 52, 1 }, // 52 : NR-Unlicensed ?
          { 53, 3 }, // Trusted-WLAN => WLAN (AN-Trusted represent trusting)
          { 54, 1 }, // 54 : Trusted-Non-3GPP ?
          { 55, 1 }, // 55 : Wireline-Access ?
          { 56, 1 }, // 56 : Wireline-Cable-Access ?
          { 57, 1 }, // 57 : Wireline-BPF-Access ?

          { 101, 101 }, // 101 : IEEE-802.16e
          { 102, 2003 }, // 3GPP2-eHRPD => EHRPD
          { 103, 2001 }, // 3GPP2-HRPD => HRPD
          { 104, 2001 }, // 3GPP2-1xRTT => HRPD ?
          { 105, 2002 } // 3GPP2-UMB => UMB
        }
      {}

      uint32_t convert(uint32_t val)
      {
        auto it = replace_values_.find(val);
        if (it != replace_values_.end())
        {
          return it->second;
        }

        throw DiameterPacketFiller::IncompatibleType(
          std::string("Can't convert unknown radius RAT-Type value: ") + std::to_string(val));
      }

      static RadiusRATTypeToDiameterRATTypeConverter&
      instance()
      {
        static RadiusRATTypeToDiameterRATTypeConverter val;
        return val;
      }

    private:
      std::unordered_map<uint32_t, uint32_t> replace_values_;
    };

    // RadiusRATTypeToDiameterRATTypeFillVisitor
    class RadiusRATTypeToDiameterRATTypeFillVisitor
    {
    public:
      RadiusRATTypeToDiameterRATTypeFillVisitor(Value& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        uint32_t int_val = std::stoi(val);

        try
        {
          int_val = std::stoi(val);
        }
        catch (const std::invalid_argument&)
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill 4 bytes by value: ") + val);
        }

        result_ = dpi::Value(
          std::in_place_type<uint64_t>,
          RadiusRATTypeToDiameterRATTypeConverter::instance().convert(int_val));
      }

      void
      operator()(int64_t val)
      {
        if (val < 0 || val > std::numeric_limits<uint32_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill 4 bytes by value: ") + std::to_string(val));
        }

        result_ = dpi::Value(
          std::in_place_type<uint64_t>,
          RadiusRATTypeToDiameterRATTypeConverter::instance().convert(val));
      }

      void
      operator()(uint64_t val)
      {
        if (val > std::numeric_limits<uint32_t>::max())
        {
          throw DiameterPacketFiller::IncompatibleType(
            std::string("Can't fill 4 bytes by value: ") + std::to_string(val));
        }

        result_ = dpi::Value(
          std::in_place_type<uint64_t>,
          RadiusRATTypeToDiameterRATTypeConverter::instance().convert(val));
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = val;
      }

    private:
      Value& result_;
    };
  };

  // DefaultDiameterFieldAdapter
  struct DefaultDiameterFieldAdapter: public DiameterFieldAdapter
  {
    Value adapt(const Value& value) const override
    {
      return value;
    }
  };

  // IPv4As4BytesDiameterFieldAdapter
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

  // IntAs4BytesDiameterFieldAdapter
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

  // IntAsByteDiameterFieldAdapter
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

  // TimezoneAs2BytesDiameterFieldAdapter
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

  // ToStringDiameterFieldAdapter
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

  // RadiusRATTypeToDiameterRATTypeDiameterFieldAdapter
  class RadiusRATTypeToDiameterRATTypeDiameterFieldAdapter: public DiameterFieldAdapter
  {
  public:
    virtual Value adapt(const Value& value) const
    {
      Value result;
      RadiusRATTypeToDiameterRATTypeFillVisitor visitor(result);
      std::visit(visitor, value);
      return result;
    }
  };

  // DiameterFieldAdapterDictionary
  DiameterFieldAdapterDictionary::DiameterFieldAdapterDictionary()
    : default_adapter_(std::make_shared<DefaultDiameterFieldAdapter>())
  {
    adapters_.emplace("ipv4-as-4bytes", std::make_shared<IPv4As4BytesDiameterFieldAdapter>());
    adapters_.emplace("timezone-as-2bytes", std::make_shared<TimezoneAs2BytesDiameterFieldAdapter>());
    adapters_.emplace("int-as-4bytes", std::make_shared<IntAs4BytesDiameterFieldAdapter>());
    adapters_.emplace("int-as-1byte", std::make_shared<IntAsByteDiameterFieldAdapter>());
    adapters_.emplace("to-string", std::make_shared<ToStringDiameterFieldAdapter>());
    adapters_.emplace(
      "radius-rat-type-to-diameter-rat-type",
      std::make_shared<RadiusRATTypeToDiameterRATTypeDiameterFieldAdapter>());
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
