#include <iostream>
#include <sstream>

#include <dpi/SessionKeyEvaluator.hpp>

using namespace dpi;

bool parse_simple_ip_mask()
{
  static const char* TEST_NAME = "parse_simple_ip_mask";

  IpMask ip_mask = string_to_ip_mask("127.127.127.127");
  
  if (ip_mask.fixed_bits != 32)
  {
    std::cerr << TEST_NAME << ": unexpected fixed_bits = " << ip_mask.fixed_bits <<
      " instead 32" << std::endl;
    return false;
  }

  if (ip_mask.ip_mask != 0x7F7F7F7F)
  {
    std::cerr << TEST_NAME << ": unexpected value = " << ip_mask.ip_mask <<
      " instead " << 0x7F7F7F7F << std::endl;
    return false;
  }

  auto ips = ip_mask.expand();

  if (ips.size() != 1 || *ips.begin() != 0x7F7F7F7F)
  {
    std::cerr << TEST_NAME << ": unexpected ips size after expand: " << ips.size() <<
      " instead 1" << std::endl;
    return false;
  }

  if (*ips.begin() != 0x7F7F7F7F)
  {
    std::cerr << TEST_NAME << ": unexpected ip after expand" << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

bool parse_simple_ip_mask2()
{
  static const char* TEST_NAME = "parse_simple_ip_mask2";

  IpMask ip_mask = string_to_ip_mask("127.127.127.127/31");
  
  if (ip_mask.fixed_bits != 31)
  {
    std::cerr << TEST_NAME << ": unexpected fixed_bits = " << ip_mask.fixed_bits <<
      " instead 32" << std::endl;
    return false;
  }

  if (ip_mask.ip_mask != 0x7F7F7F7E)
  {
    std::cerr << TEST_NAME << ": unexpected value = " << ip_mask.ip_mask <<
      " instead " << 0x7F7F7F7F << std::endl;
    return false;
  }

  auto ips = ip_mask.expand();

  if (ips.size() != 2 || ips[0] != 0x7F7F7F7E || ips[1] != 0x7F7F7F7F)
  {
    std::cerr << TEST_NAME << ": unexpected ips after expand" << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

bool test_all_match()
{
  static const char* TEST_NAME = "test all match";

  IpMask ip_mask = string_to_ip_mask("*");

  if (ip_mask.fixed_bits != 0)
  {
    std::cerr << TEST_NAME << ": unexpected fixed_bits = " << ip_mask.fixed_bits <<
      " instead 32" << std::endl;
    return false;
  }

  if (ip_mask.ip_mask != 0)
  {
    std::cerr << TEST_NAME << ": unexpected value = " << ip_mask.ip_mask <<
      " instead " << 0 << std::endl;
    return false;
  }

  return true;
}

bool base_test()
{
  static const char* TEST_NAME = "base test";

  IpMask ip_mask = string_to_ip_mask("127.127.127.127/24");

  if (ip_mask.fixed_bits != 24)
  {
    std::cerr << TEST_NAME << ": unexpected fixed_bits = " << ip_mask.fixed_bits <<
      " instead 24" << std::endl;
    return false;
  }

  if (ip_mask.ip_mask != 0x7F7F7F00)
  {
    std::cerr << TEST_NAME << ": unexpected value = " << ip_mask.ip_mask <<
      " instead " << 0x7F7F7F00 << std::endl;
    return false;
  }

  return true;
}

bool base_test2()
{
  static const char* TEST_NAME = "base test2";

  {
    IpMask ip_mask = string_to_ip_mask("127.127.127.*");

    if (ip_mask.fixed_bits != 24)
    {
      std::cerr << TEST_NAME << ", scenario #1: unexpected fixed_bits = " << ip_mask.fixed_bits <<
        " instead 24" << std::endl;
      return false;
    }

    if (ip_mask.ip_mask != 0x7F7F7F00)
    {
      std::cerr << TEST_NAME << ", scenario #1: unexpected value = " << ip_mask.ip_mask <<
        " instead " << 0x7F7F7F00 << std::endl;
      return false;
    }
  }
  
  {
    IpMask ip_mask = string_to_ip_mask("127.127.*");

    if (ip_mask.fixed_bits != 16)
    {
      std::cerr << TEST_NAME << ", scenario #2: unexpected fixed_bits = " << ip_mask.fixed_bits <<
        " instead 16" << std::endl;
      return false;
    }

    if (ip_mask.ip_mask != 0x7F7F0000)
    {
      std::cerr << TEST_NAME << ", scenario #2: unexpected value = " << ip_mask.ip_mask <<
        " instead " << 0x7F7F0000 << std::endl;
      return false;
    }
  }

  {
    IpMask ip_mask = string_to_ip_mask("127.*");

    if (ip_mask.fixed_bits != 8)
    {
      std::cerr << TEST_NAME << ", scenario #3: unexpected fixed_bits = " << ip_mask.fixed_bits <<
        " instead 16" << std::endl;
      return false;
    }

    if (ip_mask.ip_mask != 0x7F000000)
    {
      std::cerr << TEST_NAME << ", scenario #3: unexpected value = " << ip_mask.ip_mask <<
        " instead " << 0x7F000000 << std::endl;
      return false;
    }
  }

  return true;
}

int main()
{
  bool res = true;

  if (!parse_simple_ip_mask())
  {
    res = false;
  }

  if (!parse_simple_ip_mask2())
  {
    res = false;
  }

  if (!test_all_match())
  {
    res = false;
  }

  if (!base_test())
  {
    res = false;
  }

  if (!base_test2())
  {
    res = false;
  }

  return res ? 0 : -1;
}
