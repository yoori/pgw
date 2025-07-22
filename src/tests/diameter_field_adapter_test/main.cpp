#include <iostream>
#include <sstream>

#include <gears/StringManip.hpp>
#include <dpi/Utils.hpp>

using namespace dpi;

bool test_bcd_encode()
{
  static const char* TEST_NAME = "test_bcd_encode";

  {
    auto res = bcd_encode("3572487790592201");
    std::string hex_res = Gears::StringManip::hex_encode(&res[0], res.size(), false);
    if (hex_res != "5327847709952210")
    {
      std::cerr << TEST_NAME << ": unexpected value on step #1: " << hex_res << std::endl;
      return false;
    }
  }

  {
    auto res = bcd_encode("572487790592201");
    std::string hex_res = Gears::StringManip::hex_encode(&res[0], res.size(), false);
    if (hex_res != "5027847709952210")
    {
      std::cerr << TEST_NAME << ": unexpected value on step #2: " << hex_res << std::endl;
      return false;
    }
  }

  std::cout << TEST_NAME << ": success" << std::endl;

  return true;
}

int main()
{
  bool res = true;

  if (!test_bcd_encode())
  {
    res = false;
  }

  return res ? 0 : -1;
}
