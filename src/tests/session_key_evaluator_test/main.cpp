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
    dpi::SessionKeyEvaluator::IpMask(0x7F000000, 32),
    std::nullopt,
    dpi::SessionKeyEvaluator::IpMask(),
    std::nullopt,
    dpi::SessionKey("test", "")
    ));

  auto s = evaluator.evaluate(FlowTraits(0x7F000000, std::nullopt, 0, std::nullopt, "proto"));
  std::cout << "S1: " << s.to_string() << std::endl;

  return true;
}

int main()
{
  bool res = true;

  if (!base_test())
  {
    res = false;
  }

  return res ? 0 : -1;
}
