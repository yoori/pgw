#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include <gears/Singleton.hpp>

#include <gears/CompositeActiveObject.hpp>
#include <dpi/PacketProcessor.hpp>
#include <dpi/DPIRunner.hpp>

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
  auto user_storage = std::make_shared<dpi::UserStorage>();
  processor = std::make_shared<Processor>(user_storage);
  std::string config_path_str(config_path, config_path_len);
  processor->load_config(config_path_str);

  // init DPI
  auto packet_processor = std::make_shared<dpi::PacketProcessor>(user_storage);
  auto dpi_runner = std::make_shared<dpi::DPIRunner>(config_path_str, packet_processor);
  all_active_objects->add_child_object(dpi_runner);
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
