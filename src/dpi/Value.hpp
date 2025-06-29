#pragma once

#include <variant>

namespace dpi
{
  using ByteArrayValue = std::vector<uint8_t>;
  using Value = std::variant<uint64_t, int64_t, std::string, ByteArrayValue>;
}
