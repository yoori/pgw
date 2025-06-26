#include <gears/AppUtils.hpp>

#include <dpi/Config.hpp>
#include <dpi/NDPIPacketProcessor.hpp>
#include <dpi/NetInterfaceNDPIProcessor.hpp>
#include <dpi/NetInterfaceBridgeNDPIProcessor.hpp>
#include <dpi/StatUserSessionPacketProcessor.hpp>
#include <dpi/MainUserSessionPacketProcessor.hpp>
#include <dpi/Manager.hpp>
#include <dpi/InputDiameterRequestProcessor.hpp>
#include <dpi/IOServiceActiveObject.hpp>
#include <dpi/SessionRuleOverrideUserSessionPacketProcessor.hpp>

#include "RadiusServerImpl.hpp"
#include "Processor.hpp"

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
  //args.add(Gears::AppUtils::equal_name("http-port"), opt_http_port);
  args.parse(argc - 1, argv + 1);

  if (opt_config->empty())
  {
    std::cerr << "config should be defined" << std::endl;
    return 1;
  }

  signal(SIGINT, sigproc);

  auto all_active_objects = std::make_shared<Gears::CompositeActiveObject>();
  auto config = dpi::Config::read(*opt_config);

  dpi::PccConfigProviderPtr pcc_config_provider;

  if (!config.pcc_config_file.empty())
  {
    pcc_config_provider = std::make_shared<dpi::PccConfigProvider>(config.pcc_config_file);
    all_active_objects->add_child_object(pcc_config_provider);
  }

  // init radius listener
  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);

  dpi::DiameterSessionPtr gx_diameter_session;

  if (config.gx_diameter_url.has_value())
  {
    auto sctp_connection = std::make_shared<dpi::SCTPConnection>(
      nullptr,
      config.gx_diameter_url->local_endpoints,
      config.gx_diameter_url->connect_endpoints
    );

    sctp_connection->connect();

    std::vector<std::string> local_ips;
    for (const auto& local_endpoint : config.gx_diameter_url->local_endpoints)
    {
      local_ips.emplace_back(local_endpoint.host);
    }

    dpi::DiameterSession::make_exchange(
      *sctp_connection,
      config.gx_diameter_url->origin_host,
      config.gx_diameter_url->origin_realm,
      !config.gx_diameter_url->destination_host.empty() ?
        std::optional<std::string>(config.gx_diameter_url->destination_host) :
        std::optional<std::string>(),
      config.gx_diameter_url->destination_realm,
      "Traflab PGW",
      std::vector<uint32_t>({16777238, 4}),
      local_ips
    );

    auto gx_connection = sctp_connection; // std::make_shared<dpi::SCTPStreamConnection>(sctp_connection, 1);

    //auto connection_keeper = std::make_shared<dpi::ConnectionKeeper>(sctp_connection);
    //all_active_objects->add_child_object(connection_keeper);

    gx_diameter_session = std::make_shared<dpi::DiameterSession>(
      nullptr,
      gx_connection,
      config.gx_diameter_url->origin_host,
      config.gx_diameter_url->origin_realm,
      !config.gx_diameter_url->destination_host.empty() ?
        std::optional<std::string>(config.gx_diameter_url->destination_host) :
        std::optional<std::string>(),
      config.gx_diameter_url->destination_realm,
      16777238, //< Gx
      "3GPP Gx"
    );

    all_active_objects->add_child_object(gx_diameter_session);
  }

  dpi::DiameterSessionPtr gy_diameter_session = gx_diameter_session;

  /*
  if (config.gy_diameter_url.has_value())
  {
    auto gy_connection = std::make_shared<dpi::SCTPStreamConnection>(sctp_connection, 2);

    gy_diameter_session = std::make_shared<dpi::DiameterSession>(
      nullptr,
      gy_connection,
      config.gy_diameter_url->origin_host,
      config.gy_diameter_url->origin_realm,
      config.gy_diameter_url->destination_host,
      config.gy_diameter_url->destination_realm,
      4, //< DCCA = 4
      "Diameter Credit Control Application"
    );

    all_active_objects->add_child_object(gy_diameter_session);
  }
  */

  auto user_storage = std::make_shared<dpi::UserStorage>(
    nullptr, session_rule_config);
  auto user_session_storage = std::make_shared<dpi::UserSessionStorage>(
    nullptr);

  auto manager = std::make_shared<dpi::Manager>(
    user_storage,
    user_session_storage,
    gx_diameter_session,
    gy_diameter_session,
    pcc_config_provider
  );

  if (gx_diameter_session)
  {
    auto input_diameter_request_processor = std::make_shared<dpi::InputDiameterRequestProcessor>(
      config.gx_diameter_url->origin_host,
      config.gx_diameter_url->origin_realm,
      gx_diameter_session,
      manager
    );

    gx_diameter_session->set_request_processor(
      [input_diameter_request_processor](const Diameter::Packet& packet)
      {
        input_diameter_request_processor->process(packet);
      }
    );
  }

  auto processor = std::make_shared<dpi::Processor>(manager);
  processor->load_config(*opt_config);

  if (gx_diameter_session)
  {
    std::ostringstream ostr;
    ostr << "  local_endpoints: " << config.gx_diameter_url->local_endpoints.size() << std::endl <<
      "  connect_endpoints: " << config.gx_diameter_url->connect_endpoints.size() << std::endl;
    processor->logger()->log(ostr.str());
    gx_diameter_session->set_logger(processor->logger());
  }

  user_storage->set_event_logger(processor->event_logger());

  // init DPI
  auto event_processor = std::make_shared<dpi::EventProcessor>(
    processor->event_logger(),
    config.dump_stat_root);

  all_active_objects->add_child_object(event_processor);

  auto main_user_session_packet_processor = std::make_shared<dpi::MainUserSessionPacketProcessor>(
    user_storage,
    user_session_storage,
    event_processor,
    pcc_config_provider);
  main_user_session_packet_processor->set_session_rule_config(session_rule_config);

  auto composite_user_session_packet_processor = std::make_shared<dpi::CompositeUserSessionPacketProcessor>();
  composite_user_session_packet_processor->add_child_object(
    main_user_session_packet_processor);

  if (pcc_config_provider)
  {
    auto session_rule_override_user_session_packet_processor =
      std::make_shared<dpi::SessionRuleOverrideUserSessionPacketProcessor>(
        pcc_config_provider);
    composite_user_session_packet_processor->add_child_object(
      session_rule_override_user_session_packet_processor);
  }

  if (!config.dump_stat_root.empty())
  {
    auto stat_user_session_packet_processor = std::make_shared<dpi::StatUserSessionPacketProcessor>(
      config.dump_stat_root);
    composite_user_session_packet_processor->add_child_object(
      stat_user_session_packet_processor);
    all_active_objects->add_child_object(stat_user_session_packet_processor);
  }

  auto packet_processor = std::make_shared<dpi::PacketProcessor>(
    user_storage,
    user_session_storage,
    composite_user_session_packet_processor,
    processor->event_logger(),
    config.ip_rules_root,
    gx_diameter_session,
    gy_diameter_session,
    pcc_config_provider);

  if (config.http_port > 0)
  {
    auto http_server = std::make_shared<dpi::HttpServer>(
      processor->logger(),
      user_storage,
      user_session_storage,
      event_processor,
      config.http_port,
      ""
    );
    all_active_objects->add_child_object(http_server);
  }

  std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor =
    std::make_shared<dpi::NDPIPacketProcessor>(
      config,
      0 // datalink_type
    );

  auto client_interface = std::make_shared<dpi::PcapNetInterface>(
    config.interface.c_str());

  auto server_interface = std::make_shared<dpi::PcapNetInterface>(
    config.interface2.c_str());

  auto bridge = std::make_shared<dpi::NetInterfaceBridgeNDPIProcessor>(
    ndpi_packet_processor,
    packet_processor,
    client_interface,
    server_interface,
    1,
    processor->logger()
    );

  /*
  auto dpi_processor = std::make_shared<dpi::NetInterfaceNDPIProcessor>(
    ndpi_packet_processor,
    client_interface
    );
  */

  ndpi_packet_processor->set_datalink_type(
    (int)pcap_datalink(client_interface->pcap_handle()));

  all_active_objects->add_child_object(bridge);

  auto io_service_active_object = std::make_shared<dpi::IOServiceActiveObject>();

  dpi::RadiusServerImpl server(
    io_service_active_object->io_service(),
    config.radius_secret,
    config.radius_port,
    "/usr/share/freeradius/dictionary",
    processor);

  all_active_objects->add_child_object(io_service_active_object);

  all_active_objects->activate_object();

  interrupter->activate_object();
  interrupter->wait_object();

  all_active_objects->deactivate_object();
  all_active_objects->wait_object();

  std::cout << "Exit application" << std::endl;

  return 0;
}
