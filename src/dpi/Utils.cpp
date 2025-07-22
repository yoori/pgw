#include "Utils.hpp"

namespace dpi
{
  // convert value by Binary-Coded Decimal (BCD)
  std::vector<uint8_t>
  bcd_encode(const std::string& val)
  {
    std::vector<uint8_t> res;
    res.reserve(val.size() / 2 + val.size() % 2);

    uint8_t add_byte = 0;
    int cur_byte_block_offset = 0;

    if (val.size() % 2 > 0)
    {
      cur_byte_block_offset = 1;
    }

    for (const auto& digit_sym : val)
    {
      add_byte = add_byte | (static_cast<uint8_t>(digit_sym - '0') << (cur_byte_block_offset * 4));

      if (cur_byte_block_offset == 1)
      {
        res.emplace_back(add_byte);
        cur_byte_block_offset = 0;
        add_byte = 0;
      }
      else
      {
        ++cur_byte_block_offset;
      }
    }

    return res;
  }
}
