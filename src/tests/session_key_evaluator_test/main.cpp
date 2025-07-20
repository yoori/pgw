#include <iostream>
#include <sstream>

#include <dpi/SessionKeyEvaluator.hpp>

using namespace dpi;

bool src_ip_match_test()
{
  static const char* TEST_NAME = "src ip match test";

  auto mark_key = dpi::SessionKey("", "test");
  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    mark_key
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF00, std::nullopt, 0, std::nullopt, "proto"));
    if (s != mark_key)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << mark_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0, std::nullopt, "proto"));
    if (s != mark_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << mark_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFE00, std::nullopt, 0, std::nullopt, "proto"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #3: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

bool dst_ip_match_test()
{
  static const char* TEST_NAME = "dst ip match test";

  auto mark_key = dpi::SessionKey("", "test");
  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    mark_key
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0, std::nullopt, 0xFFFFFF00, std::nullopt, "proto"));
    if (s != mark_key)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << mark_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0, std::nullopt, 0xFFFFFF01, std::nullopt, "proto"));
    if (s != mark_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << mark_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0, std::nullopt, 0xFFFFFE00, std::nullopt, "proto"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #3: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

bool src_ip_dst_ip_match_test()
{
  static const char* TEST_NAME = "src dst ip match test";

  auto mark_key = dpi::SessionKey("", "test");
  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    mark_key
    ));

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF00, std::nullopt, 0, std::nullopt, "proto"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0, std::nullopt, "proto"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0xFFFFFF01, std::nullopt, "proto"));
    if (s != mark_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << mark_key.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

bool src_port_match_test()
{
  static const char* TEST_NAME = "src port match test";

  auto mark_key1 = dpi::SessionKey("", "test1");
  auto mark_key2 = dpi::SessionKey("", "test2");

  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(),
    10000,
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    mark_key1
    ));
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    2,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF01, 24),
    10001,
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    mark_key2
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF00, 10000, 0, std::nullopt, "proto"));
    if (s != mark_key1)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << mark_key1.to_string() << std::endl;
      return false;
    }
  }

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF01, 10001, 0, std::nullopt, "proto"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, 10001, 0, std::nullopt, "proto"));
    if (s != mark_key2)
    {
      std::cerr << TEST_NAME << ": step #3: unexpected session key = " << s.to_string() <<
        " instead " << mark_key2.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

bool dst_port_match_test()
{
  static const char* TEST_NAME = "dst port match test";

  auto mark_key1 = dpi::SessionKey("", "test1");
  auto mark_key2 = dpi::SessionKey("", "test2");

  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    10000,
    mark_key1
    ));
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    2,
    std::string(),
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF01, 24),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    10001,
    mark_key2
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF00, std::nullopt, 0, 10000, "proto"));
    if (s != mark_key1)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << mark_key1.to_string() << std::endl;
      return false;
    }
  }

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF01, std::nullopt, 0, 10001, "proto"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0, 10001, "proto"));
    if (s != mark_key2)
    {
      std::cerr << TEST_NAME << ": step #3: unexpected session key = " << s.to_string() <<
        " instead " << mark_key2.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

bool proto_match_test()
{
  static const char* TEST_NAME = "proto match test";

  auto mark_key1 = dpi::SessionKey("", "test1");
  auto mark_key2 = dpi::SessionKey("", "test2");

  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    "proto1",
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    10000,
    mark_key1
    ));
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    2,
    "proto2",
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    10001,
    mark_key2
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF00, std::nullopt, 0, 10000, "proto1"));
    if (s != mark_key1)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << mark_key1.to_string() << std::endl;
      return false;
    }
  }

  {
    auto expected_key = dpi::SessionKey();
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF01, std::nullopt, 0, 10002, "proto1"));
    if (s != expected_key)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << expected_key.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0, 10001, "proto2"));
    if (s != mark_key2)
    {
      std::cerr << TEST_NAME << ": step #3: unexpected session key = " << s.to_string() <<
        " instead " << mark_key2.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

bool priority_match_test()
{
  static const char* TEST_NAME = "priority match test";

  auto mark_key1 = dpi::SessionKey("", "test1");
  auto mark_key2 = dpi::SessionKey("", "test2");
  auto mark_key3 = dpi::SessionKey("", "test3");

  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    "proto1",
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    10000,
    mark_key1
    ));
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    2,
    "proto1",
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    mark_key2
    ));
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    3,
    "proto1",
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    10000,
    mark_key3
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF00, std::nullopt, 0, 10000, "proto1"));
    if (s != mark_key3)
    {
      std::cerr << TEST_NAME << ": step #1: unexpected session key = " << s.to_string() <<
        " instead " << mark_key3.to_string() << std::endl;
      return false;
    }
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xAFFFFF01, std::nullopt, 0, 10001, "proto1"));
    if (s != mark_key2)
    {
      std::cerr << TEST_NAME << ": step #2: unexpected session key = " << s.to_string() <<
        " instead " << mark_key2.to_string() << std::endl;
      return false;
    }
  }

  return true;
}

int main()
{
  bool res = true;

  if (!src_ip_match_test())
  {
    res = false;
  }

  if (!dst_ip_match_test())
  {
    res = false;
  }

  if (!src_ip_dst_ip_match_test())
  {
    res = false;
  }

  if (!src_port_match_test())
  {
    res = false;
  }

  if (!dst_port_match_test())
  {
    res = false;
  }

  if (!proto_match_test())
  {
    res = false;
  }

  if (!priority_match_test())
  {
    res = false;
  }

  return res ? 0 : -1;
}
