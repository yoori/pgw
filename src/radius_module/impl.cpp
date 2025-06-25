//#include <freeradius-devel/server/base.h>

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
#include <dpi/SessionRuleOverrideUserSessionPacketProcessor.hpp>
#include <dpi/ConnectionKeeper.hpp>
#include <dpi/InputDiameterRequestProcessor.hpp>

#include <http_server/HttpServer.hpp>

#include "Processor.hpp"

extern "C" {
#include "impl.h"
}

Gears::CompositeActiveObject_var all_active_objects = nullptr;
ProcessorPtr processor;

enum VPType
{
  FR_TYPE_STRING,
  FR_TYPE_IPV4_ADDR,
  FR_TYPE_UINT32,
  FR_TYPE_UINT8,
  FR_UNKNOWN
};

struct VPNode
{
  void* value;
  VPType type;
  VPNode* next;
  VPNode* child_nodes;
};

void log_message(std::string_view msg)
{
  std::ostringstream ostr;
  ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] [sber-telecom] TRACE: " <<
    msg << std::endl;
  std::cout << ostr.str() << std::flush;
}

bool tel_gateway_process_request(
  unsigned int acct_status_type,
  const char* calling_station_id_buf,
  int calling_station_id_len,
  const char* called_station_id_buf,
  int called_station_id_len,
  uint32_t framed_ip_address,
  uint32_t nas_ip_address,
  const char* imsi_buf,
  const char* imei_buf,
  uint8_t rat_type,
  const char* mcc_mnc,
  uint8_t tz,
  uint32_t sgsn_address,
  uint32_t access_network_charging_address,
  uint32_t charging_id,
  const char* gprs_negotiated_qos_profile,
  const void* user_location_info,
  int user_location_info_len,
  const char* nsapi_buf,
  int nsapi_len,
  const char* selection_mode_buf,
  int selection_mode_len,
  const char* charging_characteristics_buf,
  int charging_characteristics_len
)
{
  std::cout << ">>> imsi_buf: " << (imsi_buf ? imsi_buf : "NULL") << std::endl;
  std::cout << ">>> tz: " << (unsigned int)tz << std::endl;
  std::cout << ">>> sgsn_address: " << sgsn_address << std::endl;
  std::string_view calling_station_id = calling_station_id_buf ?
    std::string_view(calling_station_id_buf, calling_station_id_len) :
    std::string_view();
  std::string_view called_station_id = called_station_id_buf ?
    std::string_view(called_station_id_buf, called_station_id_len) :
    std::string_view();
  std::vector<unsigned char> user_location_info_buf(
    static_cast<const unsigned char*>(user_location_info),
    static_cast<const unsigned char*>(user_location_info) + user_location_info_len);
  std::string_view nsapi = nsapi_buf ?
    std::string_view(nsapi_buf, nsapi_len) : std::string_view();
  std::string_view selection_mode = selection_mode_buf ?
    std::string_view(selection_mode_buf, selection_mode_len) : std::string_view();
  std::string_view charging_characteristics = charging_characteristics_buf ?
    std::string_view(charging_characteristics_buf, charging_characteristics_len) :
    std::string_view();

  processor->process_request(
    static_cast<dpi::Manager::AcctStatusType>(acct_status_type),
    calling_station_id, //< msisdn
    called_station_id, //< APN
    imsi_buf ? std::string_view(imsi_buf) : std::string_view(),
    imei_buf ? std::string_view(imei_buf) : std::string_view(),
    framed_ip_address,
    nas_ip_address,
    rat_type,
    mcc_mnc,
    tz,
    sgsn_address,
    access_network_charging_address,
    charging_id,
    gprs_negotiated_qos_profile,
    user_location_info_buf,
    nsapi,
    selection_mode,
    charging_characteristics
  );

  return true;
}

void tel_gateway_initialize(const char* config_path, int config_path_len)
{
  all_active_objects = std::make_shared<Gears::CompositeActiveObject>();

  log_message("initialize");

  auto config = dpi::Config::read(config_path);

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

  processor = std::make_shared<Processor>(manager);
  std::string config_path_str(config_path, config_path_len);
  processor->load_config(config_path_str);

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
