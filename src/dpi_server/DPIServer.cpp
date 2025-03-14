#include <gears/AppUtils.hpp>

#include <dpi/DPIRunner.hpp>
#include <http_server/HttpServer.hpp>

int main(int argc, char **argv)
{
  // read config
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_config;
  Gears::AppUtils::Option<unsigned int> opt_http_port(8080);
  args.add(Gears::AppUtils::equal_name("config") || Gears::AppUtils::short_name("y"), opt_config);
  args.add(Gears::AppUtils::equal_name("http-port"), opt_http_port);
  args.parse(argc - 1, argv + 1);

  if (opt_config->empty())
  {
    std::cerr << "config should be defined" << std::endl;
    return 1;
  }

  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);

  auto composite_active_object = std::make_shared<Gears::CompositeActiveObject>();
  auto logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto event_logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto user_storage = std::make_shared<dpi::UserStorage>(event_logger, session_rule_config);
  auto packet_processor = std::make_shared<dpi::PacketProcessor>(user_storage, event_logger);
  auto http_server = std::make_shared<dpi::HttpServer>(
    logger,
    user_storage,
    *opt_http_port,
    ""
  );
  auto runner = std::make_shared<dpi::DPIRunner>(*opt_config, packet_processor);
  composite_active_object->add_child_object(http_server);

  composite_active_object->activate_object();

  runner->activate_object();
  runner->wait_object();

  composite_active_object->deactivate_object();
  composite_active_object->wait_object();

  return 0;
}
