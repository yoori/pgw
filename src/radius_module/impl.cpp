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
#include <dpi/NetInterfaceNDPIProcessor.hpp>
#include <dpi/MainUserSessionPacketProcessor.hpp>

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
  uint32_t nas_ip_address
)
{
  std::string_view called_station_id = called_station_id_buf ?
    std::string_view(called_station_id_buf, called_station_id_len) :
    std::string_view();

  processor->process_request(called_station_id, framed_ip_address, nas_ip_address);
  return true;
}

void tel_gateway_initialize(const char* config_path, int config_path_len)
{
  all_active_objects = std::make_shared<Gears::CompositeActiveObject>();

  log_message("initialize");

  // init radius listener
  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);

  auto user_storage = std::make_shared<dpi::UserStorage>(nullptr, session_rule_config);
  processor = std::make_shared<Processor>(user_storage);
  std::string config_path_str(config_path, config_path_len);
  processor->load_config(config_path_str);

  user_storage->set_event_logger(processor->event_logger());

  // init DPI
  auto main_user_session_packet_processor = std::make_shared<dpi::MainUserSessionPacketProcessor>(
    user_storage,
    processor->event_logger());
  main_user_session_packet_processor->set_session_rule_config(session_rule_config);

  auto composite_user_session_packet_processor =
    std::make_shared<dpi::CompositeUserSessionPacketProcessor>();
  composite_user_session_packet_processor->add_child_object(
    main_user_session_packet_processor);

  auto packet_processor = std::make_shared<dpi::PacketProcessor>(
    user_storage,
    composite_user_session_packet_processor,
    processor->event_logger());

  std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor =
    std::make_shared<dpi::NDPIPacketProcessor>(
      config_path,
      packet_processor,
      0 // datalink_type
    );

  auto config = dpi::Config::read(config_path);

  auto client_interface = std::make_shared<dpi::NetInterface>(
    config.interface.c_str());

  auto dpi_processor = std::make_shared<dpi::NetInterfaceNDPIProcessor>(
    ndpi_packet_processor,
    client_interface
    );

  ndpi_packet_processor->set_datalink_type(
    (int)pcap_datalink(client_interface->pcap_handle()));

  all_active_objects->add_child_object(dpi_processor);
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
