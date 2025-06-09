#include <iostream>

#include <dpi/User.hpp>


int main()
{
  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);
  const dpi::SessionKey telegram_session_key("telegram", std::string());
  const dpi::SessionKey gosuslugi_session_key("https", "gosuslugi");

  const Gears::Time start_time = Gears::Time::get_time_of_day();
  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("89263411124"), std::string("88888888"));
  user->process_packet(session_rule_config, telegram_session_key, start_time, 1000);
  user->process_packet(session_rule_config, telegram_session_key, start_time + Gears::Time(10), 1000);

  std::cout << "=== STEP1 ===" << std::endl << user->to_json_string() << std::endl;

  user->process_packet(session_rule_config,
    telegram_session_key, start_time + Gears::Time(41), 1000);

  std::cout << "=== STEP2 ===" << std::endl << user->to_json_string() << std::endl;

  user->process_packet(session_rule_config,
    telegram_session_key, start_time + Gears::Time::ONE_DAY + Gears::Time(41), 1000);

  std::cout << "=== STEP3 ===" << std::endl << user->to_json_string() << std::endl;

  user->process_packet(session_rule_config,
    gosuslugi_session_key, start_time + Gears::Time::ONE_DAY + Gears::Time(41), 1000);

  std::cout << "=== STEP4 ===" << std::endl << user->to_json_string() << std::endl;

  return 0;
}
