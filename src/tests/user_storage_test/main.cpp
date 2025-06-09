#include <iostream>

#include <dpi/UserStorage.hpp>


int main()
{
  dpi::SessionRuleConfig session_rule_config;
  auto event_logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto user_storage = std::make_shared<dpi::UserStorage>(event_logger, session_rule_config);
  user_storage->add_user("89263411124", "88888888", 1);

  return 0;
}
