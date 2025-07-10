#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace dpi
{
  using ByteArrayValue = std::vector<uint8_t>;
  using Value = std::variant<uint64_t, int64_t, std::string, ByteArrayValue>;

  std::string value_as_string(const Value& val);
}
