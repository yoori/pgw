#include <iostream>
#include <sstream>

#include <dpi/SessionKeyEvaluator.hpp>

using namespace dpi;

bool base_test()
{
  static const char* TEST_NAME = "base test";

  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    //dpi::SessionKeyEvaluator::IpMask(0x7F000000, 24),
    //dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 25),
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKey("test", "")
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF00, std::nullopt, 0, std::nullopt, "proto"));
    std::cout << TEST_NAME << ": S1: " << s.to_string() << std::endl;
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0, std::nullopt, "proto"));
    std::cout << TEST_NAME << ": S2: " << s.to_string() << std::endl;
  }

  return true;
}

bool base_test2()
{
  static const char* TEST_NAME = "base test2";

  SessionKeyEvaluator evaluator;
  evaluator.add_rule(dpi::SessionKeyEvaluator::SessionKeyRule(
    1,
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(0xFFFFFF00, 24),
    std::nullopt,
    dpi::SessionKey("test", "")
    ));

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF00, std::nullopt, 0, std::nullopt, "proto"));
    std::cout << TEST_NAME << ": S1: " << s.to_string() << std::endl;
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0, std::nullopt, "proto"));
    std::cout << TEST_NAME << ": S2: " << s.to_string() << std::endl;
  }

  {
    auto s = evaluator.evaluate(FlowTraits(0xFFFFFF01, std::nullopt, 0xFFFFFF01, std::nullopt, "proto"));
    std::cout << TEST_NAME << ": S3: " << s.to_string() << std::endl;
  }

  return true;
}

int main()
{
  bool res = true;

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
