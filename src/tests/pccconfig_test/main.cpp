#include <iostream>

#include <gears/AppUtils.hpp>

#include <dpi/PccConfig.hpp>

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_config_file_path("config.json");
  Gears::AppUtils::StringOption opt_result_config_file_path("result_config.json");
  Gears::AppUtils::CheckOption opt_dump_session_keys;

  args.add(Gears::AppUtils::equal_name("config"), opt_config_file_path);
  args.add(Gears::AppUtils::equal_name("result-config"), opt_result_config_file_path);
  args.add(Gears::AppUtils::equal_name("dump-session-keys"), opt_dump_session_keys);

  args.parse(argc - 1, argv + 1);

  dpi::ConstPccConfigPtr pcc_config = dpi::PccConfig::read(*opt_config_file_path);

  if (opt_dump_session_keys.enabled())
  {
    for (const auto& [session_key, session_rule] : pcc_config->session_rule_by_session_key)
    {
      std::cout << session_key.to_string() << ": "
        "priority = " << session_rule->priority <<
        ", allow_traffic = " << session_rule->allow_traffic <<
        std::endl;
    }
  }

  pcc_config->save(*opt_result_config_file_path);

  return 0;
}
