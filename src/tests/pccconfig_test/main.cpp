#include <iostream>

#include <gears/AppUtils.hpp>

#include <dpi/PccConfig.hpp>

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_config_file_path("config.json");
  Gears::AppUtils::StringOption opt_result_config_file_path("result_config.json");

  args.add(Gears::AppUtils::equal_name("config"), opt_config_file_path);
  args.add(Gears::AppUtils::equal_name("result-config"), opt_result_config_file_path);

  args.parse(argc - 1, argv + 1);

  dpi::ConstPccConfigPtr pcc_config = dpi::PccConfig::read(*opt_config_file_path);
  pcc_config->save(*opt_result_config_file_path);

  return 0;
}
