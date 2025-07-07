#include <iostream>

#include <dpi/UserStorage.hpp>
#include <dpi/UserSessionStorage.hpp>

int main()
{
  dpi::SessionRuleConfig session_rule_config;
  auto logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto event_logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto user_storage = std::make_shared<dpi::UserStorage>(event_logger, session_rule_config);
  auto user_session_storage = std::make_shared<dpi::UserSessionStorage>(logger);
  auto user = user_storage->add_user("89263411124");
  dpi::UserSessionTraits user_session_traits;
  user_session_traits.framed_ip_address = 1;

  auto user_session = user_session_storage->add_user_session(user_session_traits, nullptr, user);
  auto user_session_by_gx_session_suffix = user_session_storage->get_user_session_by_gx_session_suffix(
    user_session->gx_session_suffix());

  std::cout << (user_session_by_gx_session_suffix ? "session found" : "session not found") << std::endl;

  return 0;
}
