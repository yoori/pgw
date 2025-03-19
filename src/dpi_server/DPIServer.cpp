#include <gears/AppUtils.hpp>

#include <dpi/Config.hpp>
#include <dpi/NDPIPacketProcessor.hpp>
#include <dpi/NetInterfaceNDPIProcessor.hpp>
#include <dpi/NetInterfaceBridgeNDPIProcessor.hpp>
#include <dpi/StatUserSessionPacketProcessor.hpp>
#include <dpi/MainUserSessionPacketProcessor.hpp>
#include <http_server/HttpServer.hpp>

std::shared_ptr<Gears::ActiveObject> interrupter;

void sigproc(int)
{
  if (interrupter)
  {
    interrupter->deactivate_object();
  }
}

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

  auto config = dpi::Config::read(*opt_config);

  auto composite_active_object = std::make_shared<Gears::CompositeActiveObject>();
  auto logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto event_logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto user_storage = std::make_shared<dpi::UserStorage>(event_logger, session_rule_config);

  auto main_user_session_packet_processor = std::make_shared<dpi::MainUserSessionPacketProcessor>(
    user_storage, event_logger);
  main_user_session_packet_processor->set_session_rule_config(session_rule_config);

  auto composite_user_session_packet_processor = std::make_shared<dpi::CompositeUserSessionPacketProcessor>();
  composite_user_session_packet_processor->add_child_object(
    main_user_session_packet_processor);

  if (!config.dump_stat_root.empty())
  {
    auto stat_user_session_packet_processor = std::make_shared<dpi::StatUserSessionPacketProcessor>(
      config.dump_stat_root);
    composite_user_session_packet_processor->add_child_object(
      stat_user_session_packet_processor);
    composite_active_object->add_child_object(stat_user_session_packet_processor);
  }

  auto packet_processor = std::make_shared<dpi::PacketProcessor>(
    user_storage,
    composite_user_session_packet_processor,
    event_logger);

  auto http_server = std::make_shared<dpi::HttpServer>(
    logger,
    user_storage,
    *opt_http_port,
    ""
  );

  std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor =
    std::make_shared<dpi::NDPIPacketProcessor>(
      *opt_config,
      packet_processor,
      0 // datalink_type
    );

  auto interface = std::make_shared<dpi::NetInterface>(config.interface.c_str());

  if (config.interface2.empty())
  {
    std::cout << "Start in listener mode" << std::endl;
    auto dpi_processor = std::make_shared<dpi::NetInterfaceNDPIProcessor>(
      ndpi_packet_processor,
      interface
    );
    interrupter = dpi_processor;
  }
  else
  {
    // bridge mode
    std::cout << "Start in bridge mode" << std::endl;

    auto interface2 = std::make_shared<dpi::NetInterface>(config.interface2.c_str());
    auto bridge = std::make_shared<dpi::NetInterfaceBridgeNDPIProcessor>(
      ndpi_packet_processor,
      interface,
      interface2
    );
    interrupter = bridge;
  }

  signal(SIGINT, sigproc);

  ndpi_packet_processor->set_datalink_type(
    (int)pcap_datalink(interface->pcap_handle()));

  composite_active_object->add_child_object(http_server);
  composite_active_object->activate_object();

  interrupter->activate_object();
  interrupter->wait_object();

  composite_active_object->deactivate_object();
  composite_active_object->wait_object();

  std::cout << "Exit application" << std::endl;

  return 0;
}
