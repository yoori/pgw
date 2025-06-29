#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <sstream>

#include <rapidjson/document.h>

#include <gears/OutputMemoryStream.hpp>

#include <Diameter/Packet.hpp>

#include <dpi/AVPUtils.hpp>
#include <dpi/UserSessionTraits.hpp>
#include "Processor.hpp"


const std::string LOG_PREFIX = "[tel-gateway] ";

namespace dpi
{
  Processor::Processor(
    LoggerPtr logger,
    LoggerPtr event_logger,
    ManagerPtr manager)
    : logger_(std::move(logger)),
      event_logger_(std::move(event_logger)),
      manager_(std::move(manager))
  {}

  void Processor::load_config(std::string_view config_path)
  {
    static const char* FUN = "Config::load_config()";

    std::ostringstream ostr;
    ostr << LOG_PREFIX << "Loading config: '" << config_path << "'" << std::endl;
    std::cout << ostr.str() << std::endl;

    config_path_ = std::string(config_path);

    std::string diameter_url;
    std::string diameter_origin_host;
    std::string diameter_origin_realm;

    std::string config_text;

    // read config file into string
    if (!config_path_.empty())
    {
      std::ifstream config_file_istr(config_path_);
      std::string line;
      while(std::getline(config_file_istr, line))
      {
        config_text += line;
      }

      rapidjson::Document document;
      document.Parse(config_text.c_str());

      if (document.HasMember("processing_log_file"))
      {
        logger_ = std::make_shared<dpi::FileLogger>(
          document["processing_log_file"].GetString());
      }

      if (document.HasMember("event_log_file"))
      {
        event_logger_ = std::make_shared<dpi::FileLogger>(
          document["event_log_file"].GetString());
      }
    }
  }

  /*
  bool Processor::process_request(
    dpi::Manager::AcctStatusType acct_status_type,
    std::string_view calling_station_id, //< msisdn
    std::string_view called_station_id, //< msisdn
    std::string_view imsi,
    std::string_view imei,
    uint32_t framed_ip_address,
    uint32_t nas_ip_address,
    uint8_t rat_type,
    std::string_view mcc_mnc,
    uint8_t tz,
    uint32_t sgsn_ip_address,
    uint32_t access_network_charging_ip_address,
    uint32_t charging_id,
    const char* gprs_negotiated_qos_profile,
    const std::vector<unsigned char>& user_location_info,
    std::string_view nsapi,
    std::string_view selection_mode,
    std::string_view charging_characteristics
  )
  */

  bool Processor::process_request(
    dpi::Manager::AcctStatusType acct_status_type,
    std::string_view calling_station_id, //< msisdn
    uint32_t framed_ip_address,
    const std::unordered_map<ConstAttributeKeyPtr, Value>& pass_attributes,
    const UserSessionTraits& user_session_traits
  )
  {
    std::cout << "process radius request" << std::endl;
    logger_->log("process radius request");

    bool result = false;

    /*
    dpi::UserSessionTraits user_session_traits;
    user_session_traits.framed_ip_address = framed_ip_address;
    user_session_traits.msisdn = calling_station_id;
    user_session_traits.imei = imei;
    user_session_traits.imsi = imsi;
    user_session_traits.called_station_id = called_station_id;
    user_session_traits.nas_ip_address = nas_ip_address;
    user_session_traits.rat_type = rat_type;
    user_session_traits.timezone = timezone;
    user_session_traits.mcc_mnc = mcc_mnc;
    user_session_traits.sgsn_ip_address = sgsn_ip_address;
    user_session_traits.access_network_charging_ip_address = access_network_charging_ip_address;
    user_session_traits.charging_id = charging_id;
    user_session_traits.gprs_negotiated_qos_profile = gprs_negotiated_qos_profile ?
      gprs_negotiated_qos_profile : "";
    user_session_traits.user_location_info = user_location_info;
    user_session_traits.nsapi = nsapi;
    user_session_traits.selection_mode = selection_mode;
    */

    result = manager_->process_request(acct_status_type, user_session_traits);

    std::cout << "Radius: return " << result <<
      ", acct_status_type = " << (int)acct_status_type <<
      ", msisdn = " << calling_station_id <<
      std::endl;

    return result;
  }
}
