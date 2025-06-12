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


Processor::Processor(
  dpi::UserStoragePtr user_storage,
  dpi::UserSessionStoragePtr user_session_storage,
  dpi::DiameterSessionPtr gx_diameter_session,
  dpi::DiameterSessionPtr gy_diameter_session
  )
  : user_storage_(std::move(user_storage)),
    user_session_storage_(std::move(user_session_storage)),
    gx_diameter_session_(std::move(gx_diameter_session)),
    gy_diameter_session_(std::move(gy_diameter_session)),
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
  const char* gprs_negotiated_qos_profile
)
{
  logger_->log("process radius request");

  dpi::UserPtr user;
  dpi::UserSessionPtr user_session;

  if (!called_station_id.empty() && framed_ip_address != 0)
  {
    user = user_storage_->add_user(called_station_id);
  }

  if (!user)
  {
    user = std::make_shared<dpi::User>(std::string());
  }

  if (framed_ip_address != 0)
  {
    user_session = user_session_storage_->get_user_session_by_ip(framed_ip_address);

    if (!user_session)
    {
      dpi::UserSessionTraits user_session_traits;
      user_session_traits.framed_ip_address = framed_ip_address;
      user_session_traits.msisdn = called_station_id;
      user_session_traits.nas_ip_address = nas_ip_address;
      user_session_traits.rat_type = rat_type;
      user_session_traits.timezone = timezone;
      user_session_traits.mcc_mnc = mcc_mnc;
      user_session_traits.sgsn_ip_address = sgsn_ip_address;
      user_session_traits.access_network_charging_ip_address = access_network_charging_ip_address;
      user_session_traits.charging_id = charging_id;
      user_session_traits.gprs_negotiated_qos_profile = gprs_negotiated_qos_profile;

      user_session = user_session_storage_->add_user_session(
        user_session_traits,
        user
      );
    }
  }

  if (gx_diameter_session_)
  {
    try
    {
      logger_->log("send diameter cc init");

      dpi::DiameterSession::Request request;
      request.msisdn = called_station_id;
      request.imsi = imsi;
      request.framed_ip_address = framed_ip_address;
      request.nas_ip_address = nas_ip_address;
      request.rat_type = rat_type;
      request.timezone = tz;
      request.mcc_mnc = mcc_mnc;

      request.sgsn_ip_address = sgsn_ip_address;
      request.access_network_charging_ip_address = access_network_charging_ip_address;
      request.charging_id = charging_id;
      request.gprs_negotiated_qos_profile = gprs_negotiated_qos_profile ?
        gprs_negotiated_qos_profile : "";

      std::cout << "========= REQUEST" << std::endl <<
        request.to_string() << std::endl <<
        "========================" << std::endl;

      dpi::DiameterSession::GxInitResponse response = gx_diameter_session_->send_gx_init(request);

      {
        std::ostringstream ostr;
        ostr << "diameter cc init response code: " << response.result_code;
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
