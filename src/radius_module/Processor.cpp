#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <sstream>

#include <rapidjson/document.h>

#include <gears/OutputMemoryStream.hpp>

#include <Diameter/Packet.hpp>

#include <dpi/AVPUtils.hpp>
#include "Processor.hpp"


const std::string LOG_PREFIX = "[tel-gateway] ";


Processor::Processor(
  dpi::UserStoragePtr user_storage,
  DiameterSessionPtr diameter_session)
  : user_storage_(std::move(user_storage)),
    diameter_session_(std::move(diameter_session)),
    logger_(std::make_shared<dpi::StreamLogger>(std::cout)),
    event_logger_(std::make_shared<dpi::StreamLogger>(std::cout))
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

    /*
    if (document.HasMember("diameter_url"))
    {
      const auto& diameter_url_obj = document["diameter_url"];

      std::vector<DiameterSession::Endpoint> local_endpoints;
      if (diameter_url_obj.HasMember("local_endpoints"))
      {
	for (const auto& local_endpoint_json : diameter_url_obj["local_endpoints"].GetArray())
	{
	  local_endpoints.emplace_back(DiameterSession::Endpoint(
	    local_endpoint_json["host"].GetString(),
	    local_endpoint_json.HasMember("port") ? local_endpoint_json["port"].GetInt() : 0
	    ));
	}
      }

      std::vector<DiameterSession::Endpoint> connect_endpoints;
      if (diameter_url_obj.HasMember("connect_endpoints"))
      {
	for (const auto& endpoint_json : diameter_url_obj["connect_endpoints"].GetArray())
	{
	  connect_endpoints.emplace_back(DiameterSession::Endpoint(
	    endpoint_json["host"].GetString(),
	    endpoint_json["port"].GetInt()
	    ));
	}
      }

      diameter_session_ = std::make_unique<DiameterSession>(
        local_endpoints,
        connect_endpoints,
        diameter_url_obj["origin-host"].GetString(),
        diameter_url_obj["origin-realm"].GetString(),
	diameter_url_obj.HasMember("destination-host") ?
          std::optional<std::string>(diameter_url_obj["destination-host"].GetString()) :
	  std::nullopt
        );
    }
    */
  }
}

bool Processor::process_request(
  std::string_view called_station_id,
  uint32_t framed_ip_address,
  uint32_t nas_ip_address
)
{
  logger_->log("process radius request");

  if (!called_station_id.empty() && framed_ip_address != 0)
  {
    user_storage_->add_user(called_station_id, framed_ip_address);
  }

  if (diameter_session_)
  {
    try
    {
      logger_->log("send diameter cc init");

      unsigned int code = diameter_session_->send_cc_init(
        std::string(called_station_id), //< MSISDN
	1, //< Service-Id
	framed_ip_address, //< User IP address
	nas_ip_address
        );

      {
        std::ostringstream ostr;
        ostr << "diameter cc init response code: " << code;
        logger_->log(ostr.str());
      }
    }
    catch(const std::exception& ex)
    {
      logger_->log(std::string("send diameter cc init error: ") + ex.what());
    }
  }

  return false;
}
