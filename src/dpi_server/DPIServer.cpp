#include <gears/AppUtils.hpp>

#include <dpi/DPIRunner.hpp>


int main(int argc, char **argv)
{
  // read config
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_config;
  args.add(Gears::AppUtils::equal_name("config") || Gears::AppUtils::short_name("y"), opt_config);
  args.parse(argc - 1, argv + 1);

  if (opt_config->empty())
  {
    std::cerr << "config should be defined" << std::endl;
    return 1;
  }

  auto user_storage = std::make_shared<dpi::UserStorage>();
  auto packet_processor = std::make_shared<dpi::PacketProcessor>(user_storage);
  auto runner = std::make_shared<dpi::DPIRunner>(*opt_config, packet_processor);
  runner->activate_object();
  runner->wait_object();

  return 0;
}
