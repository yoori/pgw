#include <boost/functional/hash.hpp>

#include <gears/AppUtils.hpp>

#include <dpi/Config.hpp>
#include <dpi/DiameterSession.hpp>
#include <dpi/DummyDiameterSession.hpp>
#include <dpi/InputDiameterRequestProcessor.hpp>

#include <dpi/NDPIPacketProcessor.hpp>
#include <dpi/NetInterfaceNDPIProcessor.hpp>
#include <dpi/NetInterfaceBridgeNDPIProcessor.hpp>
#include <dpi/StatUserSessionPacketProcessor.hpp>
#include <dpi/MainUserSessionPacketProcessor.hpp>

#include <dpi/Manager.hpp>
#include <dpi/IOServiceActiveObject.hpp>
#include <dpi/SessionRuleOverrideUserSessionPacketProcessor.hpp>

#include "RadiusServer.hpp"
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

namespace dpi
{
  ConstAttributeKeyPtrSet
  resolve_attribute_keys(const std::vector<Config::Diameter::PassAttribute>& pass_attributes)
  {
    ConstAttributeKeyPtrSet result;
    for (const auto& pass_attribute : pass_attributes)
    {
      auto attribute_key = std::make_shared<AttributeKey>();
      attribute_key->name = pass_attribute.source.name;
      attribute_key->vendor = pass_attribute.source.vendor;
      result.emplace(attribute_key);
    }

    return result;
  }
}

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

  interrupter = std::make_shared<Gears::SimpleActiveObject>();
  signal(SIGINT, sigproc);

  auto all_active_objects = std::make_shared<Gears::CompositeActiveObject>();
  auto config = dpi::Config::read(*opt_config);

  dpi::DiameterDictionary diameter_dictionary(config.diameter_dictionary);

  auto logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto event_logger = std::make_shared<dpi::StreamLogger>(std::cout);

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

  std::shared_ptr<dpi::SCTPConnection> sctp_connection;

  if (config.gx.has_value() && config.gx->diameter_url.has_value())
  {
    sctp_connection = std::make_shared<dpi::SCTPConnection>(
      nullptr,
      config.gx->diameter_url->local_endpoints,
      config.gx->diameter_url->connect_endpoints
    );

    sctp_connection->connect();

    std::vector<std::string> local_ips;
    for (const auto& local_endpoint : config.gx->diameter_url->local_endpoints)
    {
      local_ips.emplace_back(local_endpoint.host);
    }

    dpi::SCTPDiameterSession::make_exchange(
      *sctp_connection,
      config.gx->diameter_url->origin_host,
      config.gx->diameter_url->origin_realm,
      !config.gx->diameter_url->destination_host.empty() ?
        std::optional<std::string>(config.gx->diameter_url->destination_host) :
        std::optional<std::string>(),
      config.gx->diameter_url->destination_realm,
      "Traflab PGW",
      std::vector<uint32_t>({16777238, 4}),
      local_ips
    );
  }

  std::shared_ptr<dpi::SCTPDiameterSession> gx_sctp_diameter_session;
  dpi::DiameterSessionPtr gx_diameter_session;

  if (config.gx.has_value())
  {
    if (config.gx->diameter_url.has_value())
    {
      gx_sctp_diameter_session = std::make_shared<dpi::SCTPDiameterSession>(
        logger,
        diameter_dictionary,
        sctp_connection,
        config.gx->diameter_url->origin_host,
        config.gx->diameter_url->origin_realm,
        !config.gx->diameter_url->destination_host.empty() ?
          std::optional<std::string>(config.gx->diameter_url->destination_host) :
          std::optional<std::string>(),
        config.gx->diameter_url->destination_realm,
        16777238, //< Gx
        "3GPP Gx"
      );

      all_active_objects->add_child_object(gx_sctp_diameter_session);

      gx_diameter_session = gx_sctp_diameter_session;
    }
    else
    {
      gx_diameter_session = std::make_shared<dpi::DummyDiameterSession>();
    }
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

  all_active_objects->add_child_object(manager);

  if (gx_diameter_session)
  {
    auto input_diameter_request_processor = std::make_shared<dpi::InputDiameterRequestProcessor>(
      config.gx.has_value() && config.gx->diameter_url.has_value() ?
        config.gx->diameter_url->origin_host : std::string("dummy"),
      config.gx.has_value() && config.gx->diameter_url.has_value() ?
        config.gx->diameter_url->origin_realm : std::string("dummy"),
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

  auto processor = std::make_shared<dpi::Processor>(
    logger, event_logger, manager);
  processor->load_config(*opt_config);

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
      manager,
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
    manager,
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

  std::shared_ptr<dpi::RadiusServer> radius_server;
  auto io_service_active_object = std::make_shared<dpi::IOServiceActiveObject>();
  all_active_objects->add_child_object(io_service_active_object);

  all_active_objects->activate_object();

  if (config.radius.has_value()) // create RadiusServer on activated io_service !
  {
    // collect required custom attributes from radius
    dpi::ConstAttributeKeyPtrSet resolve_radius_keys;

    if (config.gx.has_value())
    {
      auto resolved_keys = dpi::resolve_attribute_keys(config.gx->pass_attributes);
      resolve_radius_keys.insert(resolved_keys.begin(), resolved_keys.end());
    }

    if (config.gy.has_value())
    {
      auto resolved_keys = dpi::resolve_attribute_keys(config.gy->pass_attributes);
      resolve_radius_keys.insert(resolved_keys.begin(), resolved_keys.end());
    }

    radius_server = std::make_shared<dpi::RadiusServer>(
      io_service_active_object->io_service(),
      config.radius->listen_port,
      config.radius->secret,
      config.radius->dictionary,
      processor,
      resolve_radius_keys);
  }
  
  interrupter->activate_object();
  interrupter->wait_object();

  all_active_objects->deactivate_object();
  all_active_objects->wait_object();

  //io_service_active_object->deactivate_object();
  //io_service_active_object->wait_object();

  std::cout << "Exit application" << std::endl;

  return 0;
}
