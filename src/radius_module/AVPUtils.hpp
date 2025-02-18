#pragma once

#include <Diameter/Packet.hpp>


Diameter::AVP
create_avp(unsigned int avp_code, Diameter::AVP::Data data);

Diameter::AVP
create_string_avp(unsigned int avp_code, const std::string& value);

Diameter::AVP
create_string_avp(unsigned int avp_code, std::string_view value);

Diameter::AVP
create_string_avp(unsigned int avp_code, const char* value);

Diameter::AVP
create_octets_avp(unsigned int avp_code, const ByteArray& value);

Diameter::AVP
create_uint32_avp(unsigned int avp_code, uint32_t val);

Diameter::AVP
create_uint64_avp(unsigned int avp_code, uint64_t val);

Diameter::AVP
create_int32_avp(unsigned int avp_code, int32_t val);

Diameter::AVP
create_int64_avp(unsigned int avp_code, int64_t val);
