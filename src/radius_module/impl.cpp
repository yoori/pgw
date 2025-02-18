#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include <gears/Singleton.hpp>

#include "Processor.hpp"

extern "C" {
#include "impl.h"
}

using ProcessorSingleton = Gears::Singleton<Processor>;

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

  ProcessorSingleton::instance().process_request(called_station_id, framed_ip_address, nas_ip_address);
  return true;
}

void tel_gateway_initialize(const char* config_path, int config_path_len)
{
  std::string config_path_str(config_path, config_path_len);
  ProcessorSingleton::instance().load_config(config_path_str);
}

void tel_gateway_load()
{
  std::cout << "tel_gateway_load" << std::endl;
}

void tel_gateway_unload()
{
  std::cout << "tel_gateway_unload" << std::endl;
}
