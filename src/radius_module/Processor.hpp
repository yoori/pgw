#pragma once

#include <gears/Exception.hpp>

#include <dpi/UserStorage.hpp>
#include <dpi/Logger.hpp>

#include "DiameterSession.hpp"

class Processor
{
public:
  DECLARE_EXCEPTION(Invalid, Gears::DescriptiveException);

  Processor(dpi::UserStoragePtr user_storage = nullptr);

  void load_config(std::string_view config_path);

  bool process_request(
    std::string_view called_station_id,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address);

  dpi::LoggerPtr logger() const;

  dpi::LoggerPtr event_logger() const;

private:
  dpi::LoggerPtr logger_;
  dpi::LoggerPtr event_logger_;
  dpi::UserStoragePtr user_storage_;
  std::string config_path_;
  std::string diameter_url_;
  std::unique_ptr<DiameterSession> diameter_session_;
};

using ProcessorPtr = std::shared_ptr<Processor>;

inline dpi::LoggerPtr
Processor::logger() const
{
  return logger_;
}

inline dpi::LoggerPtr
Processor::event_logger() const
{
  return event_logger_;
}
