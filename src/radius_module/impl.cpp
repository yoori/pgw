#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include <gears/Singleton.hpp>

#include <gears/CompositeActiveObject.hpp>

#include <dpi/Config.hpp>
#include <dpi/PacketProcessor.hpp>
//#include <dpi/DPIRunner.hpp>
#include <dpi/NDPIPacketProcessor.hpp>
//#include <dpi/NetInterfaceNDPIProcessor.hpp>
#include <dpi/NetInterfaceBridgeNDPIProcessor.hpp>
#include <dpi/MainUserSessionPacketProcessor.hpp>
#include <dpi/StatUserSessionPacketProcessor.hpp>

#include <http_server/HttpServer.hpp>

#include "Processor.hpp"

extern "C" {
#include "impl.h"
}

Gears::CompositeActiveObject_var all_active_objects = nullptr;
ProcessorPtr processor;

void log_message(std::string_view msg)
{
  std::ostringstream ostr;
  ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] [sber-telecom] TRACE: " <<
    msg << std::endl;
  std::cout << ostr.str() << std::flush;
}

bool tel_gateway_process_request(
  const char* called_station_id_buf,
  int called_station_id_len,
  uint32_t framed_ip_address,
  uint32_t nas_ip_address,
  const char* imsi_buf,
  uint8_t rat_type,
  const char* mcc_mnc,
  uint8_t tz,
  uint32_t sgsn_address,
  uint32_t access_network_charging_address,
  uint32_t charging_id,
  const char* gprs_negotiated_qos_profile
)
{
  std::cout << ">>> imsi_buf: " << (imsi_buf ? imsi_buf : "NULL") << std::endl;
  std::cout << ">>> tz: " << (unsigned int)tz << std::endl;
  std::string_view called_station_id = called_station_id_buf ?
    std::string_view(called_station_id_buf, called_station_id_len) :
    std::string_view();

  processor->process_request(
    called_station_id,
    imsi_buf ? std::string_view(imsi_buf) : std::string_view(),
    framed_ip_address,
    nas_ip_address,
    rat_type,
    mcc_mnc,
    tz,
    sgsn_address,
    access_network_charging_address,
    charging_id,
    gprs_negotiated_qos_profile
  );

  return true;
}

void tel_gateway_initialize(const char* config_path, int config_path_len)
{
  all_active_objects = std::make_shared<Gears::CompositeActiveObject>();

  log_message("initialize");

  auto config = dpi::Config::read(config_path);

  // init radius listener
  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);

  dpi::DiameterSessionPtr diameter_session;

  if (config.diameter_url.has_value())
  {
    diameter_session = std::make_shared<dpi::DiameterSession>(
      nullptr,
      config.diameter_url->local_endpoints,
      config.diameter_url->connect_endpoints,
      config.diameter_url->origin_host,
      config.diameter_url->origin_realm,
      config.diameter_url->destination_host,
      std::nullopt,
      16777238, //< Gx
      "3GPP Gx"
    );
  }

  auto user_storage = std::make_shared<dpi::UserStorage>(nullptr, session_rule_config);
  processor = std::make_shared<Processor>(user_storage, diameter_session);
  std::string config_path_str(config_path, config_path_len);
  processor->load_config(config_path_str);

  if (diameter_session)
  {
    std::ostringstream ostr;
    ostr << "  local_endpoints: " << config.diameter_url->local_endpoints.size() << std::endl <<
      "  connect_endpoints: " << config.diameter_url->connect_endpoints.size() << std::endl;
    processor->logger()->log(ostr.str());
    diameter_session->set_logger(processor->logger());
  }

  user_storage->set_event_logger(processor->event_logger());

  // init DPI
  auto event_processor = std::make_shared<dpi::EventProcessor>(
    processor->event_logger(),
    config.dump_stat_root);

  all_active_objects->add_child_object(event_processor);

  auto main_user_session_packet_processor = std::make_shared<dpi::MainUserSessionPacketProcessor>(
    user_storage,
    event_processor);
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
    all_active_objects->add_child_object(stat_user_session_packet_processor);
  }

  auto packet_processor = std::make_shared<dpi::PacketProcessor>(
    user_storage,
    composite_user_session_packet_processor,
    processor->event_logger(),
    config.ip_rules_root,
    diameter_session);

  if (config.http_port > 0)
  {
    auto http_server = std::make_shared<dpi::HttpServer>(
      processor->logger(),
      user_storage,
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
  all_active_objects->activate_object();
}

void tel_gateway_load()
{
}

void tel_gateway_unload()
{
  log_message("unload");

  processor.reset();

  if (all_active_objects)
  {
    all_active_objects->deactivate_object();
    all_active_objects->wait_object();
    all_active_objects.reset();
  }
}
