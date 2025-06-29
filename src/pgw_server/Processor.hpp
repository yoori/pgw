#pragma once

#include <gears/Exception.hpp>

#include <radproto/packet_reader.h>

#include <dpi/UserStorage.hpp>
#include <dpi/UserSessionStorage.hpp>
#include <dpi/Logger.hpp>

#include <dpi/DiameterSession.hpp>
#include <dpi/PccConfigProvider.hpp>
#include <dpi/Manager.hpp>
#include <dpi/Value.hpp>
#include <dpi/Attribute.hpp>

namespace dpi
{
  class Processor
  {
  public:
    DECLARE_EXCEPTION(Invalid, Gears::DescriptiveException);

  public:
    Processor(
      LoggerPtr logger,
      dpi::LoggerPtr event_logger,
      dpi::ManagerPtr manager);

    void
    load_config(std::string_view config_path);

    bool
    process_request(
      dpi::Manager::AcctStatusType acct_status_type,
      std::string_view calling_station_id,
      uint32_t framed_ip_address,
      const std::unordered_map<ConstAttributeKeyPtr, Value>& pass_attributes,
      const UserSessionTraits& user_session_traits
      );

    /*
    bool process_request(
      dpi::Manager::AcctStatusType acct_status_type,
      std::string_view called_station_id,
      std::string_view calling_station_id,
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
      const char* gprs_negotiated_qos_profile,
      const std::vector<unsigned char>& user_location_info,
      std::string_view nsapi,
      std::string_view selection_mode,
      std::string_view charging_characteristics
    );
    */

    dpi::LoggerPtr logger() const;

    dpi::LoggerPtr event_logger() const;

  private:
    dpi::LoggerPtr logger_;
    dpi::LoggerPtr event_logger_;
    dpi::ManagerPtr manager_;

    //dpi::UserStoragePtr user_storage_;
    //dpi::UserSessionStoragePtr user_session_storage_;
    std::string config_path_;
    //std::string diameter_url_;
    //dpi::DiameterSessionPtr gx_diameter_session_;
    //dpi::DiameterSessionPtr gy_diameter_session_;
    //dpi::PccConfigProviderPtr pcc_config_provider_;
  };

  using ProcessorPtr = std::shared_ptr<Processor>;
}

namespace dpi
{
  // Processor impl
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
}
