#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <sstream>

#include <gears/OutputMemoryStream.hpp>

#include <Diameter/Packet.hpp>

#include <dpi/AVPUtils.hpp>
#include <dpi/UserSessionTraits.hpp>

#include "Manager.hpp"

namespace dpi
{
  const std::string LOG_PREFIX = "[manager] ";

  Manager::Manager(
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
      logger_(std::make_shared<dpi::StreamLogger>(std::cout))
  {}

  template<typename GxResponseType>
  void
  Manager::fill_gy_request_(
    DiameterSession::GyRequest& gy_request,
    UserSession& user_session,
    const UserSessionTraits& user_session_traits,
    const GxResponseType& response,
    const dpi::ConstPccConfigPtr& pcc_config)
  {
    std::unordered_set<unsigned long> rating_groups;

    std::cout << "XXX: FROM GX REQUEST: response.charging_rule_names.size() = " <<
      response.charging_rule_names.size() << std::endl;

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

    const auto [gy_session_id_suffix, gy_request_id] = user_session.generate_gy_request_id();

    gy_request.application_id = GY_APPLICATION_ID_;
    gy_request.session_id_suffix = gy_session_id_suffix;
    gy_request.request_id = gy_request_id;
    gy_request.user_session_traits = user_session_traits;

    for (const auto& rg_id : rating_groups)
    {
      gy_request.usage_rating_groups.emplace_back(
        dpi::DiameterSession::GyRequest::UsageRatingGroup(rg_id, 0));
    }
  }

  void
  Manager::fill_limits_by_gy_response_(
    UserSession& user_session,
    const DiameterSession::GyResponse& gy_response,
    const dpi::ConstPccConfigPtr& pcc_config)
  {
    dpi::UserSession::SetLimitArray set_limits;

    for (const dpi::DiameterSession::GyResponse::RatingGroupLimit& rating_group_limit :
      gy_response.rating_group_limits)
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

    user_session.set_limits(set_limits);
  }

  bool
  Manager::init_gx_gy_session_(
    const dpi::UserSessionPtr& user_session,
    const dpi::UserSessionTraits& user_session_traits,
    bool /*init*/)
  {
    std::cout << "init_gx_gy_session_" << std::endl;
    dpi::ConstPccConfigPtr pcc_config;                                                                                       

    if (pcc_config_provider_)
    {
      pcc_config = pcc_config_provider_->get_config();
    }

    if (gx_diameter_session_)
    {
      try
      {
        std::cout << "init_gx_gy_session_: step #2" << std::endl;
        logger_->log("send diameter cc init");

        const auto [gx_session_id_suffix, gx_request_id] = user_session->generate_gx_request_id();

        dpi::DiameterSession::Request request;
        request.application_id = GX_APPLICATION_ID_;
        request.session_id_suffix = gx_session_id_suffix;
        request.request_id = gx_request_id;
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

        DiameterSession::GyRequest gy_request;
        fill_gy_request_(gy_request, *user_session, user_session_traits, response, pcc_config);

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

          fill_limits_by_gy_response_(*user_session, gy_init_response, pcc_config);
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
  Manager::fill_gx_gy_stats_(
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

  bool Manager::process_request(
    AcctStatusType acct_status_type,
    const UserSessionTraits& user_session_traits)
  {
    dpi::UserPtr user;
    dpi::UserSessionPtr user_session;

    if (!user_session_traits.msisdn.empty() &&
      user_session_traits.framed_ip_address != 0)
    {
      user = user_storage_->add_user(user_session_traits.msisdn);
    }

    if (!user)
    {
      user = std::make_shared<dpi::User>(std::string());
    }

    bool result = false;

    if (user_session_traits.framed_ip_address != 0)
    {
      if (acct_status_type == AcctStatusType::START ||
        acct_status_type == AcctStatusType::UPDATE)
      {
        user_session = user_session_storage_->get_user_session_by_ip(
          user_session_traits.framed_ip_address);

        if (!user_session)
        {
          //std::cout << "YYY Manager::process_request(1): msisdn = " << user_session_traits.msisdn <<
          //  ", imsi = " << user_session_traits.imsi << std::endl;

          user_session = user_session_storage_->add_user_session(
            user_session_traits,
            user
          );

          //std::cout << "YYY Manager::process_request(2): msisdn = " << user_session->traits().msisdn <<
          //  ", imsi = " << user_session->traits().imsi << std::endl;

          bool gx_gy_result = init_gx_gy_session_(
            user_session,
            user_session_traits,
            !user_session);

          if (!gx_gy_result)
          {
            user_session_storage_->remove_user_session(user_session_traits.framed_ip_address);
          }

          result = true;
        }
        else
        {
          result = !user_session->is_closed();
        }
      }
      else if(acct_status_type == AcctStatusType::STOP)
      {
        user_session = user_session_storage_->remove_user_session(
          user_session_traits.framed_ip_address);

        if (user_session)
        {
          abort_session(*user_session, true, true, true);
        }

        result = true;
      }
    }

    std::cout << "Radius: return " << result <<
      ", acct_status_type = " << (int)acct_status_type <<
      ", msisdn = " << user_session_traits.msisdn <<
      ", called-station-id = " << user_session_traits.called_station_id <<
      std::endl;

    return result;
  }

  std::string
  Manager::get_session_suffix_(const std::string& gx_session_id)
  {
    // get session suffix
    auto pos = gx_session_id.find(';');
    if (pos != std::string::npos)
    {
      return gx_session_id.substr(pos);
    }

    return gx_session_id;
  }
  
  void
  Manager::abort_session(
    const std::string& gx_session_id,
    bool terminate_radius,
    bool terminate_gx,
    bool terminate_gy)
  {
    auto session_suffix = get_session_suffix_(gx_session_id);
    auto user_session = user_session_storage_->get_user_session_by_gx_session_suffix(session_suffix);
    if (user_session)
    {
      abort_session(*user_session, terminate_radius, terminate_gx, terminate_gy);
    }
    else
    {
      logger_->log(
        std::string("[ERROR] can't find session by suffix '") +
        session_suffix + "' on terminate");
    }
  }

  void
  Manager::abort_session(
    dpi::UserSession& user_session,
    bool /*terminate_radius*/,
    bool terminate_gx,
    bool terminate_gy)
  {
    dpi::DiameterSession::GxTerminateRequest gx_terminate_request;
    dpi::DiameterSession::GyRequest gy_terminate_request;

    std::cout << "YYY terminate_gx_gy_session_: msisdn = " << user_session.traits().msisdn <<
      ", imsi = " << user_session.traits().imsi << std::endl;
    gy_terminate_request.user_session_traits = user_session.traits();
    fill_gx_gy_stats_(gx_terminate_request, gy_terminate_request, user_session);

    if (gx_diameter_session_ && terminate_gx)
    {
      try
      {
        logger_->log("send diameter gx terminate");

        const auto [gx_session_id_suffix, gx_request_id] = user_session.generate_gx_request_id();

        dpi::DiameterSession::Request request;
        request.application_id = GX_APPLICATION_ID_;
        request.session_id_suffix = gx_session_id_suffix;
        request.request_id = gx_request_id;
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

    if (gy_diameter_session_ && terminate_gy)
    {
      try
      {
        logger_->log("send diameter gy terminate");

        const auto [gy_session_id_suffix, gy_request_id] = user_session.generate_gy_request_id();
        gy_terminate_request.application_id = GY_APPLICATION_ID_;
        gy_terminate_request.session_id_suffix = gy_session_id_suffix;
        gy_terminate_request.request_id = gy_request_id;
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

    user_session.close();
  }

  void
  Manager::update_session(const std::string& gx_session_id)
  {
    auto session_suffix = get_session_suffix_(gx_session_id);
    auto user_session = user_session_storage_->get_user_session_by_gx_session_suffix(session_suffix);
    if (user_session)
    {
      update_session(*user_session);
    }
    else
    {
      logger_->log(
        std::string("[ERROR] can't find session by suffix '") +
        session_suffix + "' on update");
    }
  }

  void
  Manager::update_session(dpi::UserSession& user_session)
  {
    dpi::ConstPccConfigPtr pcc_config;                                                                                       

    if (pcc_config_provider_)
    {
      pcc_config = pcc_config_provider_->get_config();
    }

    dpi::DiameterSession::GxTerminateRequest gx_update_request;
    dpi::DiameterSession::GyRequest gy_update_request;

    gy_update_request.user_session_traits = user_session.traits();
    fill_gx_gy_stats_(gx_update_request, gy_update_request, user_session);

    // Request Gx
    if (gx_diameter_session_)
    {
      try
      {
        logger_->log("send diameter gx terminate");

        const auto [gx_session_id_suffix, gx_request_id] = user_session.generate_gx_request_id();

        dpi::DiameterSession::Request request;
        request.application_id = GX_APPLICATION_ID_;
        request.session_id_suffix = gx_session_id_suffix;
        request.request_id = gx_request_id;
        request.user_session_traits = user_session.traits();

        dpi::DiameterSession::GxUpdateResponse response = gx_diameter_session_->send_gx_update(
          request,
          gx_update_request);

        if (response.result_code != 2001)
        {
          //abort_session();
          return;
        }

        DiameterSession::GyRequest gy_request;
        fill_gy_request_(gy_request, user_session, user_session.traits(), response, pcc_config);

        {
          std::ostringstream ostr;
          ostr << "diameter gx update response code: " << response.result_code;
          logger_->log(ostr.str());
        }

        if(gy_diameter_session_)
        {
          dpi::DiameterSession::GyResponse gy_init_response = gy_diameter_session_->send_gy_update(gy_request);

          if (gy_init_response.result_code != 2001)
          {
            //abort_session();
            return;
          }

          bool any_success = false;
          for (const auto& rg : gy_init_response.rating_group_limits)
          {
            any_success = any_success || (rg.result_code == 2001);
          }

          if (!any_success)
          {
            //abort_session();
            return;
          }

          fill_limits_by_gy_response_(user_session, gy_init_response, pcc_config);
        }
      }
      catch(const std::exception& ex)
      {
        logger_->log(std::string("send diameter gx update error: ") + ex.what());
      }
    }

    // Request Gy
    if (gy_diameter_session_)
    {
      try
      {
        logger_->log("send diameter gy terminate");

        const auto [gy_session_id_suffix, gy_request_id] = user_session.generate_gy_request_id();
        gy_update_request.application_id = GY_APPLICATION_ID_;
        gy_update_request.session_id_suffix = gy_session_id_suffix;
        gy_update_request.request_id = gy_request_id;
        gy_update_request.user_session_traits = user_session.traits();

        dpi::DiameterSession::GyResponse response = gy_diameter_session_->send_gy_update(
          gy_update_request);

        {
          std::ostringstream ostr;
          ostr << "diameter gy update response code: " << response.result_code;
          logger_->log(ostr.str());
        }
      }
      catch(const std::exception& ex)
      {
        logger_->log(std::string("send diameter gy terminate error: ") + ex.what());
      }
    }
  }
}
