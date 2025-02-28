#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <sstream>

#include <rapidjson/document.h>

#include <gears/OutputMemoryStream.hpp>

#include <Diameter/Packet.hpp>

#include "AVPUtils.hpp"
#include "Processor.hpp"


const std::string LOG_PREFIX = "[tel-gateway] ";


Processor::Processor()
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
  }
}

bool Processor::process_request(
  std::string_view called_station_id,
  uint32_t framed_ip_address,
  uint32_t nas_ip_address
)
{
  std::ostringstream ostr;
  ostr << "tel_gateway_process_requestX {" <<
    "called_station_id = " << called_station_id <<
    ", framed_ip_address = " << framed_ip_address <<
    ", nas_ip_address = " << nas_ip_address << "}";
  std::cout << ostr.str() << std::endl;

  if (diameter_session_)
  {
    try
    {
      return diameter_session_->send_cc_init(
        std::string(called_station_id), //< MSISDN
	1, //< Service-Id
	framed_ip_address,
	nas_ip_address
        );
    }
    catch(const std::exception&)
    {
    }
  }

  return false;
}
