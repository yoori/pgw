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

  bool Processor::process_request(
    dpi::Manager::AcctStatusType acct_status_type,
    std::string_view calling_station_id, //< msisdn
    uint32_t framed_ip_address,
    const UserSessionTraits& user_session_traits
  )
  {
    std::cout << "process radius request: " <<
      user_session_traits.user_session_property_container->to_string() <<
      std::endl;

    logger_->log("process radius request");

    bool result = false;

    result = manager_->process_request(
      acct_status_type,
      user_session_traits);

    std::cout << "Radius: return " << result <<
      ", acct_status_type = " << (int)acct_status_type <<
      ", msisdn = " << calling_station_id <<
      std::endl;

    return result;
  }
}
