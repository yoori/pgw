#include <iostream>

#include <dpi/User.hpp>
#include <dpi/ShapingManager.hpp>

int main()
{
  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);

  const Gears::Time start_time = Gears::Time::get_time_of_day();
  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("89263411124"));

  const dpi::SessionKey key1("test1", "");
  const dpi::SessionKey key2("test2", "");

  std::vector<dpi::SessionKey> shape_session_keys{key1, key2};

  user->set_shaping(shape_session_keys, 1000);

  auto state1 = user->process_packet(session_rule_config, key1, start_time, 1000);
  std::cout << "state1.shaped = " << state1.shaped << std::endl;

  auto state2 = user->process_packet(session_rule_config, key2, start_time, 1000);
  std::cout << "state2.shaped = " << state2.shaped << std::endl;

  return 0;
}
