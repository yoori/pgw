#include "AVPUtils.hpp"

Diameter::AVP
create_avp(unsigned int avp_code, Diameter::AVP::Data data)
{
  return Diameter::AVP()
    .setHeader(
      Diameter::AVP::Header()
        .setAVPCode(avp_code)
        .setFlags(
          Diameter::AVP::Header::Flags()
            .setFlag(Diameter::AVP::Header::Flags::Bits::Mandatory, true)
          )
        )
        .setData(data)
        // Updating AVP length field, according to header and data value.
        .updateLength();
}

Diameter::AVP
create_string_avp(unsigned int avp_code, const std::string& value)
{
  return create_avp(avp_code, Diameter::AVP::Data().setOctetString(ByteArray::fromASCII(value.c_str())));
}

Diameter::AVP
create_string_avp(unsigned int avp_code, const char* value)
{
  return create_string_avp(avp_code, std::string(value));
}

Diameter::AVP
create_string_avp(unsigned int avp_code, std::string_view value)
{
  return create_avp(
    avp_code,
    Diameter::AVP::Data().setOctetString(ByteArray(
      reinterpret_cast<const ByteArray::byte*>(value.data()), value.size()
    ))
  );
}

Diameter::AVP
create_octets_avp(unsigned int avp_code, const ByteArray& value)
{
  return create_avp(avp_code, Diameter::AVP::Data().setOctetString(value));
}

Diameter::AVP
create_uint32_avp(unsigned int avp_code, uint32_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setUnsigned32(val));
}

Diameter::AVP
create_uint64_avp(unsigned int avp_code, uint64_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setUnsigned64(val));
}

Diameter::AVP
create_int32_avp(unsigned int avp_code, int32_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setInteger32(val));
}

Diameter::AVP
create_int64_avp(unsigned int avp_code, int64_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setInteger64(val));
}
