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
  dpi::DiameterSessionPtr gy_diameter_session,
  dpi::PccConfigProviderPtr pcc_config_provider
  )
  : user_storage_(std::move(user_storage)),
    user_session_storage_(std::move(user_session_storage)),
    gx_diameter_session_(std::move(gx_diameter_session)),
    gy_diameter_session_(std::move(gy_diameter_session)),
    pcc_config_provider_(std::move(pcc_config_provider)),
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

bool
Processor::init_gx_gy_session_(
  const dpi::UserSessionPtr& user_session,
  const dpi::UserSessionTraits& user_session_traits,
  bool /*init*/)
{
  std::cout << "init_gx_gy_session_" << std::endl;

  if (gx_diameter_session_)
  {
    try
    {
      std::cout << "init_gx_gy_session_: step #2" << std::endl;
      logger_->log("send diameter cc init");

      dpi::DiameterSession::Request request;
      request.user_session_traits = user_session_traits;

      std::cout << "========= REQUEST" << std::endl <<
        request.to_string() << std::endl <<
        "========================" << std::endl;

      dpi::DiameterSession::GxInitResponse response = gx_diameter_session_->send_gx_init(request);

      {
        std::ostringstream ostr;
        ostr << "diameter cc init response code: " << response.result_code;
        logger_->log(ostr.str());

        std::cout << ostr.str() << std::endl;
      }

      if (response.result_code != 2001)
      {
        return false;
      }

      dpi::ConstPccConfigPtr pcc_config;

      if (pcc_config_provider_)
      {
        pcc_config = pcc_config_provider_->get_config();
      }

      // request gy
      std::unordered_set<unsigned long> rating_groups;

      std::cout << "XXX: FROM GX REQUEST: response.charging_rule_names.size() = " <<
        response.charging_rule_names.size() <<
        ", pcc_config = " << pcc_config.get() << std::endl;

      if (pcc_config)
      {
        for (const auto& charging_rule_name : response.charging_rule_names)
        {
          auto session_rule_it = pcc_config->session_rule_by_charging_name.find(charging_rule_name);
          if (session_rule_it != pcc_config->session_rule_by_charging_name.end())
          {
            rating_groups.insert(
              session_rule_it->second.rating_groups.begin(),
              session_rule_it->second.rating_groups.end());
          }
        }
      }

      dpi::DiameterSession::GyRequest gy_request;
      gy_request.user_session_traits = user_session_traits;

      for (const auto& rg_id : rating_groups)
      {
        gy_request.usage_rating_groups.emplace_back(
          dpi::DiameterSession::GyRequest::UsageRatingGroup(rg_id, 0));
      }

      if(gy_diameter_session_)
      {
        std::cout << "XXX: TO SEND GY REQUEST: rating_groups.size() = " <<
          gy_request.usage_rating_groups.size() << std::endl;
        dpi::DiameterSession::GyResponse gy_init_response = gy_diameter_session_->send_gy_init(gy_request);

        if (gy_init_response.result_code != 2001)
        {
          return false;
        }

        bool any_success = false;
        for (const auto& rg : gy_init_response.rating_group_limits)
        {
          any_success = any_success || (rg.result_code == 2001);
        }

        if (!any_success)
        {
          return false;
        }

        dpi::UserSession::SetLimitArray set_limits;

        for (const dpi::DiameterSession::GyResponse::RatingGroupLimit& rating_group_limit :
          gy_init_response.rating_group_limits)
        {
          dpi::UserSession::SetLimit add_limit;
          auto session_rule_it = pcc_config->session_rule_by_rating_group.find(rating_group_limit.rating_group_id);
          if (session_rule_it != pcc_config->session_rule_by_rating_group.end())
          {
            add_limit.session_key = session_rule_it->second.session_key;
            if (rating_group_limit.result_code == 2001 && rating_group_limit.cc_total_octets.has_value())
            {
              add_limit.gy_limit = *rating_group_limit.cc_total_octets > 0 ? 1000000000ull : 0;
            }
            else
            {
              add_limit.gy_limit = 0;
            }
            add_limit.gy_recheck_time = Gears::Time::get_time_of_day() + rating_group_limit.validity_time;
          }

          set_limits.emplace_back(add_limit);
        }

        user_session->set_limits(set_limits);
      }
    }
    catch(const std::exception& ex)
    {
      logger_->log(std::string("send diameter cc init error: ") + ex.what());
      std::cout << (std::string("send diameter cc init error: ") + ex.what()) << std::endl;
    }
  }

  return true;
}

void
Processor::fill_gx_gy_stats_(
  dpi::DiameterSession::GxUpdateRequest& gx_request,
  dpi::DiameterSession::GyRequest& gy_request,
  const dpi::UserSession& user_session)
{
  if (!pcc_config_provider_)
  {
    return;
  }

  auto pcc_config = pcc_config_provider_->get_config();

  if (!pcc_config)
  {
    return;
  }
  
  auto used_limits = user_session.get_used_limits();
  for (const auto& used_limit : used_limits)
  {
    auto session_rule_it = pcc_config->session_keys.find(used_limit.session_key);
    if (session_rule_it != pcc_config->session_keys.end())
    {
      const dpi::PccConfig::SessionKeyRule& session_key_rule = session_rule_it->second;

      for (const auto& rg_id : session_key_rule.rating_groups)
      {
        gy_request.usage_rating_groups.emplace_back(
          dpi::DiameterSession::GyRequest::UsageRatingGroup(rg_id, used_limit.used_bytes));
      }
      
      for (const auto& mk_id : session_key_rule.monitoring_keys)
      {
        gx_request.usage_monitorings.emplace_back(
          dpi::DiameterSession::GxUpdateRequest::UsageMonitoring(
            mk_id,
            used_limit.used_bytes
          ));
      }
    }
  }
}

void
Processor::terminate_gx_gy_session_(const dpi::UserSession& user_session)
{
  dpi::DiameterSession::GxTerminateRequest gx_terminate_request;
  dpi::DiameterSession::GyRequest gy_terminate_request;

  std::cout << "YYY terminate_gx_gy_session_: msisdn = " << user_session.traits().msisdn <<
    ", imsi = " << user_session.traits().imsi << std::endl;
  gy_terminate_request.user_session_traits = user_session.traits();
  fill_gx_gy_stats_(gx_terminate_request, gy_terminate_request, user_session);

  if (gx_diameter_session_)
  {
    try
    {
      logger_->log("send diameter gx terminate");

      dpi::DiameterSession::Request request;
      request.user_session_traits = user_session.traits();

      std::cout << "========= REQUEST" << std::endl <<
        request.to_string() << std::endl <<
        "========================" << std::endl;

      dpi::DiameterSession::GxTerminateResponse response = gx_diameter_session_->send_gx_terminate(
        request,
        gx_terminate_request);

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

  if (gy_diameter_session_)
  {
    try
    {
      logger_->log("send diameter gy terminate");

      gy_terminate_request.user_session_traits = user_session.traits();

      dpi::DiameterSession::GyResponse response = gy_diameter_session_->send_gy_terminate(
        gy_terminate_request);

      {
        std::ostringstream ostr;
        ostr << "diameter gy terminate response code: " << response.result_code;
        logger_->log(ostr.str());
      }
    }
    catch(const std::exception& ex)
    {
      logger_->log(std::string("send diameter gy terminate error: ") + ex.what());
    }
  }
}

bool Processor::process_request(
  AcctStatusType acct_status_type,
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
{
  logger_->log("process radius request");

  dpi::UserPtr user;
  dpi::UserSessionPtr user_session;

  if (!calling_station_id.empty() && framed_ip_address != 0)
  {
    user = user_storage_->add_user(calling_station_id);
  }

  if (!user)
  {
    user = std::make_shared<dpi::User>(std::string());
  }

  bool result = false;

  if (framed_ip_address != 0)
  {
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

    if (acct_status_type == AcctStatusType::START ||
      acct_status_type == AcctStatusType::UPDATE)
    {
      user_session = user_session_storage_->get_user_session_by_ip(framed_ip_address);

      if (!user_session)
      {
        std::cout << "YYY Processor::process_request(1): msisdn = " << user_session_traits.msisdn <<
          ", imsi = " << user_session_traits.imsi << std::endl;

        user_session = user_session_storage_->add_user_session(
          user_session_traits,
          user
        );

        std::cout << "YYY Processor::process_request(2): msisdn = " << user_session->traits().msisdn <<
          ", imsi = " << user_session->traits().imsi << std::endl;

        bool gx_gy_result = init_gx_gy_session_(
          user_session,
          user_session_traits,
          !user_session);

        if (!gx_gy_result)
        {
          user_session_storage_->remove_user_session(user_session_traits.framed_ip_address);
        }
      }

      result = true;
    }
    else if(acct_status_type == AcctStatusType::STOP)
    {
      user_session = user_session_storage_->remove_user_session(framed_ip_address);

      if (user_session)
      {
        terminate_gx_gy_session_(*user_session);
      }

      result = true;
    }
  }

  std::cout << "Radius: return " << result <<
    ", acct_status_type = " << (int)acct_status_type <<
    ", msisdn = " << calling_station_id <<
    ", called-station-id = " << called_station_id <<
    std::endl;

  return result;
}
