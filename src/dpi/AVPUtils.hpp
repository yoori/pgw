#pragma once

#include <optional>
#include <Diameter/Packet.hpp>


Diameter::AVP
create_avp(
  unsigned int avp_code,
  Diameter::AVP::Data data,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_string_avp(
  unsigned int avp_code,
  const std::string& value,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_string_avp(
  unsigned int avp_code,
  std::string_view value,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_string_avp(
  unsigned int avp_code,
  const char* value,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_octets_avp(
  unsigned int avp_code,
  const ByteArray& value,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_uint16_avp(
  unsigned int avp_code,
  uint16_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_uint32_avp(
  unsigned int avp_code,
  uint32_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_int32_avp(
  unsigned int avp_code,
  int32_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_int64_avp(
  unsigned int avp_code,
  int64_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_uint64_avp(
  unsigned int avp_code,
  uint64_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

// Generate 6 bytes AVP. For IPv4 filled : 0x00, 0x01, {4 bytes with IPv4}
Diameter::AVP
create_ipv4_avp(
  unsigned int avp_code,
  uint32_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);

Diameter::AVP
create_ipv4_4bytes_avp(
  unsigned int avp_code,
  uint32_t val,
  std::optional<unsigned int> vendor_id = std::nullopt,
  bool mandatory = true);
