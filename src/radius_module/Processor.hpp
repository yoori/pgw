#pragma once

#include <gears/Exception.hpp>

#include <dpi/UserStorage.hpp>
#include <dpi/Logger.hpp>

#include <dpi/DiameterSession.hpp>

class Processor
{
public:
  DECLARE_EXCEPTION(Invalid, Gears::DescriptiveException);

  Processor(
    dpi::UserStoragePtr user_storage,
    dpi::DiameterSessionPtr diameter_session);

  void load_config(std::string_view config_path);

  bool process_request(
    std::string_view called_station_id,
    std::string_view imsi,
    std::string_view imei,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address,
    uint8_t rat_type,
    std::string_view mcc_mnc,
    uint8_t tz,
    uint32_t sgsn_address,
    uint32_t access_network_charging_address,
    uint32_t charging_id,
    const char* gprs_negotiated_qos_profile);

  dpi::LoggerPtr logger() const;

  dpi::LoggerPtr event_logger() const;

private:
  dpi::LoggerPtr logger_;
  dpi::LoggerPtr event_logger_;
  dpi::UserStoragePtr user_storage_;
  std::string config_path_;
  std::string diameter_url_;
  dpi::DiameterSessionPtr diameter_session_;
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
