#include "AVPUtils.hpp"

Diameter::AVP
create_avp(unsigned int avp_code, Diameter::AVP::Data data, std::optional<unsigned int> vendor_id)
{
  auto header = Diameter::AVP::Header()
    .setAVPCode(avp_code)
    .setFlags(
      Diameter::AVP::Header::Flags()
        .setFlag(Diameter::AVP::Header::Flags::Bits::Mandatory, true)
        .setFlag(Diameter::AVP::Header::Flags::Bits::VendorSpecific, vendor_id.has_value())
    );

  if (vendor_id.has_value())
  {
    header.setVendorID(*vendor_id);
  }

  return Diameter::AVP()
    .setHeader(header)
    .setData(data)
    // Updating AVP length field, according to header and data value.
    .updateLength();
}

Diameter::AVP
create_string_avp(
  unsigned int avp_code,
  const std::string& value,
  std::optional<unsigned int> vendor_id)
{
  return create_avp(
    avp_code,
    Diameter::AVP::Data().setOctetString(ByteArray::fromASCII(value.c_str())),
    vendor_id
  );
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
create_octets_avp(
  unsigned int avp_code,
  const ByteArray& value,
  std::optional<unsigned int> vendor_id)
{
  return create_avp(avp_code, Diameter::AVP::Data().setOctetString(value), vendor_id);
}

Diameter::AVP
create_uint32_avp(
  unsigned int avp_code,
  uint32_t val,
  std::optional<unsigned int> vendor_id)
{
  return create_avp(avp_code, Diameter::AVP::Data().setUnsigned32(val), vendor_id);
}

Diameter::AVP
create_uint16_avp(
  unsigned int avp_code,
  uint16_t val,
  std::optional<unsigned int> vendor_id)
{
  const uint8_t buf[] = {
    static_cast<uint8_t>((val >> 8) & 0xFF),
    static_cast<uint8_t>(0xFF)
  };
  return create_octets_avp(avp_code, ByteArray(buf, sizeof(buf)), vendor_id);
}

Diameter::AVP
create_uint64_avp(unsigned int avp_code, uint64_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setUnsigned64(val));
}

Diameter::AVP
create_int32_avp(
  unsigned int avp_code,
  int32_t val,
  std::optional<unsigned int> vendor_id)
{
  return create_avp(avp_code, Diameter::AVP::Data().setInteger32(val), vendor_id);
}

Diameter::AVP
create_int64_avp(unsigned int avp_code, int64_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setInteger64(val));
}

Diameter::AVP
create_ipv4_avp(
  unsigned int avp_code,
  uint32_t val,
  std::optional<unsigned int> vendor_id)
{
  const uint8_t addr_buf[] = {
    0,
    0x1,
    static_cast<uint8_t>((val >> 24) & 0xFF),
    static_cast<uint8_t>((val >> 16) & 0xFF),
    static_cast<uint8_t>((val >> 8) & 0xFF),
    static_cast<uint8_t>(val & 0xFF)
  };
  return create_octets_avp(
    avp_code,
    ByteArray(addr_buf, sizeof(addr_buf)),
    vendor_id
  );
}

Diameter::AVP
create_ipv4_4bytes_avp(
  unsigned int avp_code,
  uint32_t val,
  std::optional<unsigned int> vendor_id)
{
  const uint8_t addr_buf[] = {
    ((val >> 24) & 0xFF),
    ((val >> 16) & 0xFF),
    ((val >> 8) & 0xFF),
    (val & 0xFF)
  };
  return create_octets_avp(
    avp_code,
    ByteArray(addr_buf, sizeof(addr_buf)),
    vendor_id
  );
}
