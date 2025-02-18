#pragma once

#include <gears/Exception.hpp>

#include "DiameterSession.hpp"

class Processor
{
public:
  DECLARE_EXCEPTION(Invalid, Gears::DescriptiveException);

  Processor();

  void load_config(std::string_view config_path);

  bool process_request(
    std::string_view called_station_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address);

private:
  std::string config_path_;
  std::string diameter_url_;
  std::unique_ptr<DiameterSession> diameter_session_;
};
