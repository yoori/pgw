#include <iostream>
#include <sstream>

#include <dpi/SessionKeyEvaluator.hpp>

using namespace dpi;

bool test_all_match()
{
  static const char* TEST_NAME = "test all match";

  SessionKeyEvaluator::IpMask ip_mask = SessionKeyEvaluator::string_to_ip_mask("*");

  if (ip_mask.fixed_bits != 32)
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

  SessionKeyEvaluator::IpMask ip_mask = SessionKeyEvaluator::string_to_ip_mask("127.127.127.127/24");

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
    SessionKeyEvaluator::IpMask ip_mask = SessionKeyEvaluator::string_to_ip_mask("127.127.127.*");

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
    SessionKeyEvaluator::IpMask ip_mask = SessionKeyEvaluator::string_to_ip_mask("127.127.*");

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
    SessionKeyEvaluator::IpMask ip_mask = SessionKeyEvaluator::string_to_ip_mask("127.*");

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
