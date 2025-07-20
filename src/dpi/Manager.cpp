#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#include <gears/OutputMemoryStream.hpp>

#include <Diameter/Packet.hpp>

#include <dpi/AVPUtils.hpp>
#include <dpi/UserSessionTraits.hpp>

#include "CerrCallback.hpp"
#include "FunTask.hpp"

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
      logger_(std::make_shared<dpi::StreamLogger>(std::cout)),
      user_session_action_planner_(std::make_shared<UserSessionActionPlanner>())
  {
    Gears::ActiveObjectCallback_var callback(new CerrCallback());
    task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 10));
    add_child_object(task_runner_);

    add_child_object(user_session_action_planner_);
  }

  void
  Manager::init()
  {
    user_session_action_planner_->set_manager(shared_from_this());
  }

  void
  Manager::fill_gy_request_(
    DiameterSession::GyRequest& gy_request,
    UserSession& user_session,
    bool fill_zero_usage_groups)
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

    const Gears::Time now = Gears::Time::get_time_of_day();
    std::unordered_set<unsigned long> rating_groups;

    //std::cout << "XXX: FROM GX REQUEST: response.charging_rule_names.size() = " <<
    //  response.charging_rule_names.size() << std::endl;

    if (pcc_config)
    {
      std::unordered_set<std::string> charging_rule_names = user_session.charging_rule_names();

      for (const auto& charging_rule_name : charging_rule_names)
      {
        auto session_rule_it = pcc_config->session_rule_by_charging_name.find(charging_rule_name);
        if (session_rule_it != pcc_config->session_rule_by_charging_name.end())
        {
          rating_groups.insert(
            session_rule_it->second->rating_groups.begin(),
            session_rule_it->second->rating_groups.end());
        }
      }

      // DEBUG >>>>
      if (user_session.traits()->msisdn == "79662660021")
      {
        std::set<std::string> debug_charging_rule_names;
        debug_charging_rule_names.emplace("MVNO_SBT_UNLIM");

        for (const auto& charging_rule_name : debug_charging_rule_names)
        {
          auto session_rule_it = pcc_config->session_rule_by_charging_name.find(charging_rule_name);
          if (session_rule_it != pcc_config->session_rule_by_charging_name.end())
          {
            rating_groups.insert(
              session_rule_it->second->rating_groups.begin(),
              session_rule_it->second->rating_groups.end());
          }
        }
      }
    }

    std::cout << "fill_gy_request_(" << user_session.traits()->msisdn << "): " <<
      "rating_groups.size() = " << rating_groups.size() << std::endl;

    const auto [gy_session_id_suffix, gy_request_id] = user_session.generate_gy_request_id();

    gy_request.application_id = GY_APPLICATION_ID_;
    gy_request.session_id_suffix = gy_session_id_suffix;
    gy_request.request_id = gy_request_id;
    gy_request.user_session_traits = *user_session.traits();

    std::unordered_map<unsigned long, dpi::DiameterSession::GyRequest::UsageRatingGroup> send_rating_groups;

    if (fill_zero_usage_groups)
    {
      for (const auto& rg_id : rating_groups)
      {
        send_rating_groups.emplace(
          rg_id,
          DiameterSession::GyRequest::UsageRatingGroup(rg_id, OctetStats(), std::nullopt));
      }
    }

    auto used_limits = user_session.get_gy_used_limits(now, true);

    std::cout << "fill_gy_request_(" << user_session.traits()->msisdn << "): " <<
      "used_limits =";

    for (const auto& used_limit : used_limits)
    {
      std::cout << " " << used_limit.to_string();

      auto session_rule_it = pcc_config->session_keys.find(used_limit.rule_id);
      if (session_rule_it != pcc_config->session_keys.end())
      {
        const SessionKeyRule& session_key_rule = *session_rule_it->second;

        for (const auto& rg_id : session_key_rule.rating_groups)
        {
          auto& send_rating_group = send_rating_groups[rg_id];
          send_rating_group.rating_group_id = rg_id;
          send_rating_group += used_limit;
          if (used_limit.reporting_reason.has_value())
          {
            send_rating_group.reporting_reason = used_limit.reporting_reason;
          }
        }
      }
    }

    std::cout << std::endl;

    for (const auto& [_, rg_use] : send_rating_groups)
    {
      gy_request.usage_rating_groups.emplace_back(rg_use);
    }
  }

  void
  Manager::fill_limits_by_gy_response_(
    UserSession& user_session,
    DiameterSession::GyResponse& gy_response,
    const dpi::ConstPccConfigPtr& pcc_config)
  {
    UserSession::SetLimitArray set_limits;
    bool empty_session_key_added = false;

    // DEBUG >>>>
    if (user_session.traits()->msisdn == "79662660021")
    {
      bool empty_session_key_found = false;

      for (const dpi::DiameterSession::GyResponse::RatingGroupLimit& rating_group_limit :
        gy_response.rating_group_limits)
      {
        if (rating_group_limit.rating_group_id == 32)
        {
          empty_session_key_found = true;
        }
      }

      if (!empty_session_key_found)
      {
        DiameterSession::GyResponse::RatingGroupLimit empty_rg;
        empty_rg.rating_group_id = 32;
        empty_rg.cc_total_octets = 1000000000;
        empty_rg.result_code = 2001;
        gy_response.rating_group_limits.emplace_back(std::move(empty_rg));
      }
    }

    const Gears::Time now = Gears::Time::get_time_of_day();

    for (const dpi::DiameterSession::GyResponse::RatingGroupLimit& rating_group_limit :
      gy_response.rating_group_limits)
    {
      UserSession::Limit add_limit;
      auto session_rule_it = pcc_config->session_rule_by_rating_group.find(rating_group_limit.rating_group_id);
      if (session_rule_it != pcc_config->session_rule_by_rating_group.end())
      {
        add_limit.session_key_rule = session_rule_it->second;
        add_limit.gy_recheck_time = rating_group_limit.validity_time;

        for (const auto& sk : add_limit.session_key_rule->session_keys)
        {
          if (sk.traffic_type().empty() && sk.category_type().empty())
          {
            empty_session_key_added = true;
          }
        }

        if (rating_group_limit.result_code == 2001 && rating_group_limit.cc_total_octets.has_value())
        {
          if (*rating_group_limit.cc_total_octets > 0)
          {
            if (rating_group_limit.octets_threshold.has_value())
            {
              add_limit.gy_recheck_limit = *rating_group_limit.cc_total_octets - *rating_group_limit.octets_threshold;
            }
            else
            {
              add_limit.gy_recheck_limit = *rating_group_limit.cc_total_octets * 9 / 10;
            }
            add_limit.gy_limit = rating_group_limit.cc_total_octets;
          }
          else
          {
            add_limit.gy_limit = 0;
          }
        }
        else
        {
          add_limit.gy_limit = 0;
        }

        add_limit.gy_recheck_time = rating_group_limit.validity_time;
      }

      set_limits.emplace_back(add_limit);
    }

    user_session.set_gy_limits(set_limits);
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

    std::optional<Gears::Time> first_check_time;

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

        std::cout << "========= GX REQUEST" << std::endl <<
          request.to_string() << std::endl <<
          "========================" << std::endl;

        dpi::DiameterSession::GxInitResponse response = gx_diameter_session_->send_gx_init(request);

        {
          std::ostringstream ostr;
          ostr << "diameter cc init response code: " << response.result_code;
          logger_->log(ostr.str());

          //std::cout << ostr.str() << std::endl;
        }

        if (response.result_code != 2001)
        {
          return false;
        }

        if (user_session_traits.msisdn == "79662660021")
        {
          response.install_charging_rule_names.emplace("MVNO_SBT_UNLIM");
        }

        // filter and report not found chaging rules
        ChargingRuleNameSet result_charging_rule_names;
        ChargingRuleNameSet not_found_charging_rule_names;

        if (!filter_charging_rules_(
          *user_session,
          result_charging_rule_names,
          not_found_charging_rule_names,
          response.install_charging_rule_names))
        {
          abort_session(
            *user_session,
            true, //< terminate radius
            true, //< terminate gx
            false, //< terminate gy
            "Empty charging rules on Gy init",
            not_found_charging_rule_names);
          return false;
        }

        std::cout << "Manager::set_gx_revalidation_time(): " <<                                                                
          (response.revalidate_time.has_value() ? response.revalidate_time->gm_ft() : std::string("none")) << std::endl;

        user_session->set_charging_rule_names(result_charging_rule_names);
        user_session->set_revalidate_gx_time(response.revalidate_time);
      }
      catch(const std::exception& ex)
      {
        logger_->log(std::string("send diameter cc init error: ") + ex.what());
        std::cout << (std::string("send diameter cc init error: ") + ex.what()) << std::endl;
      }
    }

    if(gy_diameter_session_)
    {
      try
      {
        DiameterSession::GyRequest gy_request;
        fill_gy_request_(gy_request, *user_session, true);

        dpi::DiameterSession::GyResponse gy_init_response =
          gy_diameter_session_->send_gy_init(gy_request);

        if (gy_init_response.result_code != 2001)
        {
          abort_session(
            *user_session,
            true, //< terminate radius
            true, //< terminate gx
            false, //< don't terminate gy
            std::string("Gy init result code: ") + std::to_string(gy_init_response.result_code));
          return false;
        }

        bool any_success = false;
        for (const auto& rg : gy_init_response.rating_group_limits)
        {
          any_success = any_success || (rg.result_code == 2001);
        }

        if (!any_success)
        {
          abort_session(
            *user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            "No success rating groups on Gy init");
          return false;
        }

        fill_limits_by_gy_response_(*user_session, gy_init_response, pcc_config);
      }
      catch(const std::exception& ex)
      {
        logger_->log(std::string("send diameter gy init error: ") + ex.what());
        std::cout << (std::string("send diameter gy init error: ") + ex.what()) << std::endl;
      }
    }

    UserSession::RevalidateResult revalidation = user_session->revalidation();
    std::optional<Gears::Time> check_time = revalidation.min_time();
    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] Manager: add_user_session: " <<
      "check_time = " << (check_time.has_value() ? check_time->gm_ft() : std::string("none")) <<
      ", revalidate_gx_time = " << (revalidation.revalidate_gx_time.has_value() ? revalidation.revalidate_gx_time->gm_ft() : std::string("none")) <<
      ", revalidate_gy_time = " << (revalidation.revalidate_gy_time.has_value() ? revalidation.revalidate_gy_time->gm_ft() : std::string("none")) <<
      std::endl;
    user_session_action_planner_->add_user_session(user_session, check_time);

    return true;
  }

  bool
  Manager::filter_charging_rules_(
    dpi::UserSession& user_session,
    ChargingRuleNameSet& result_charging_rule_names,
    ChargingRuleNameSet& not_found_charging_rule_names,
    const ChargingRuleNameSet& charging_rule_names)
  {
    if (!pcc_config_provider_)
    {
      not_found_charging_rule_names = charging_rule_names;
    }

    dpi::ConstPccConfigPtr pcc_config;

    if (pcc_config_provider_)
    {
      pcc_config = pcc_config_provider_->get_config();
    }

    if (pcc_config)
    {
      for (const auto& charging_rule_name : charging_rule_names)
      {
        auto session_rule_it = pcc_config->session_rule_by_charging_name.find(charging_rule_name);
        if (session_rule_it != pcc_config->session_rule_by_charging_name.end())
        {
          result_charging_rule_names.emplace(charging_rule_name);
        }
        else
        {
          not_found_charging_rule_names.emplace(charging_rule_name);
        }
      }
    }

    if (!result_charging_rule_names.empty())
    {
      // report in Gx update not found charging rules
      if (!not_found_charging_rule_names.empty())
      {
        // send Gx update only for report rules
        const auto [gx_session_id_suffix, gx_request_id] = user_session.generate_gx_request_id();

        dpi::DiameterSession::Request request;
        request.application_id = GX_APPLICATION_ID_;
        request.session_id_suffix = gx_session_id_suffix;
        request.request_id = gx_request_id;
        request.user_session_traits = *user_session.traits();

        dpi::DiameterSession::GxUpdateRequest gx_update_request;
        gx_update_request.not_found_charging_rule_names = not_found_charging_rule_names;

        dpi::DiameterSession::GxUpdateResponse gx_response = gx_diameter_session_->send_gx_update(
          request,
          gx_update_request);

        if (gx_response.result_code != 2001)
        {
          abort_session(
            user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            std::string("Gx update(for charging rules reporting) result code: ") +
              std::to_string(gx_response.result_code)); // REVIEW
          return false;
        }

        user_session.set_revalidate_gx_time(gx_response.revalidate_time);
      }

      return true;
    }

    return false;
  }

  void
  Manager::fill_gx_stats_(
    dpi::DiameterSession::GxUpdateRequest& gx_request,
    dpi::UserSession& user_session)
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

    auto used_limits = user_session.get_gx_used_limits();
    for (const auto& used_limit : used_limits)
    {
      auto session_rule_it = pcc_config->session_keys.find(used_limit.rule_id);
      if (session_rule_it != pcc_config->session_keys.end())
      {
        const SessionKeyRule& session_key_rule = *session_rule_it->second;

        for (const auto& mk_id : session_key_rule.monitoring_keys)
        {
          gx_request.usage_monitorings.emplace_back(
            dpi::DiameterSession::GxUpdateRequest::UsageMonitoring(
              mk_id,
              used_limit
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
    std::string fail_reason = "Unknown";

    if (user_session_traits.framed_ip_address != 0)
    {
      if (acct_status_type == AcctStatusType::START ||
        acct_status_type == AcctStatusType::UPDATE)
      {
        //std::cout << "Manager::process_request(): start/update: " <<
        //  "msisdn = " << user_session_traits.msisdn <<
        //  std::endl;

        user_session = user_session_storage_->get_user_session_by_ip(
          user_session_traits.framed_ip_address);

        if (user_session && acct_status_type == AcctStatusType::START)
        {
          // drop session
          if (!user_session->is_closed())
          {
            // abort
            std::cout << "Manager::process_request(): abort and drop closed session for framed_ip_address = " <<
              user_session_traits.framed_ip_address <<
              std::endl;
            abort_session(
              *user_session,
              true, //< terminate radius
              true, //< terminate gx
              true, //< terminate gy
              "Started new session for this ip address");
          }
          else
          {
            std::cout << "Manager::process_request(): drop closed session for framed_ip_address = " <<
              user_session_traits.framed_ip_address <<
              std::endl;
          }

          user_session_storage_->remove_user_session(user_session_traits.framed_ip_address);
          user_session.reset();
        }

        if (!user_session)
        {
          user_session = user_session_storage_->add_user_session(
            user_session_traits,
            user
          );

          std::cout << "Manager::process_request(): added user session: " <<
            "msisdn = " << user_session_traits.msisdn <<
            ", gx_session_suffix = " << user_session->gx_session_suffix() <<
            std::endl;

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
        else if (user_session->is_closed())
        {
          result = false;
          fail_reason = "Session closed";
        }
        else if (acct_status_type == AcctStatusType::UPDATE)
        {
          // update Gy on radius Interim-Update
          auto event_triggers = diameter_event_checker_.check(
            user_session->traits()->user_session_property_container,
            user_session_traits.user_session_property_container);

          if (!event_triggers.empty()) // TODO: check updates on control properties
          {
            std::cout << "Manager::process_request(): update with traits changes: " << std::endl <<
              "  old: " << user_session->traits()->to_string() << std::endl <<
              "  new: " << user_session_traits.to_string() << std::endl;
            result = update_session(
              *user_session,
              true, //< update Gx on traits changes ?
              true,
              "radius Interim-Update with changes",
              std::unordered_set<std::string>(), //< install charging rule names
              std::unordered_set<std::string>(), //< remove charging rule names
              event_triggers);

            if (!result)
            {
              fail_reason = "Session update returned false";
            }
          }
          else
          {
            result = true;
          }
        }
      }
      else if(acct_status_type == AcctStatusType::STOP)
      {
        std::cout << "Manager::process_request(): stop: " <<
          "msisdn = " << user_session_traits.msisdn <<
          std::endl;

        user_session = user_session_storage_->remove_user_session(
          user_session_traits.framed_ip_address);

        if (user_session)
        {
          abort_session(
            *user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            "Radius stop");
        }

        result = true;
      }
      else
      {
        fail_reason = "Unknown acct-status-type";
      }
    }
    else
    {
      fail_reason = "No framed ip address";
    }

    std::cout << "Manager: return " << result <<
      ", acct_status_type = " << (int)acct_status_type <<
      ", msisdn = " << user_session_traits.msisdn <<
      (!result ? std::string(", fail_reason = ") + fail_reason : std::string()) <<
      ", framed_ip_address = " << ipv4_address_to_string(user_session_traits.framed_ip_address) <<
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
    bool terminate_gy,
    const std::string& reason)
  {
    auto session_suffix = get_session_suffix_(gx_session_id);

    auto user_session = user_session_storage_->get_user_session_by_gx_session_suffix(session_suffix);

    if (user_session)
    {
      abort_session(*user_session, terminate_radius, terminate_gx, terminate_gy, reason);
    }
    else
    {
      logger_->log(
        std::string("[ERROR] can't find session by suffix '") +
        session_suffix + "' on terminate");

      throw UnknownSession(std::string("Unknown session: ") + gx_session_id);
    }
  }

  void
  Manager::abort_session(
    dpi::UserSession& user_session,
    bool terminate_radius,
    bool terminate_gx,
    bool terminate_gy,
    const std::string& reason,
    const std::optional<ChargingRuleNameSet>& not_found_charging_rule_names)
  {
    std::cout << "Manager::abort_session(): msisdn = " << user_session.traits()->msisdn <<
      ", terminate_radius = " << terminate_radius <<
      ", terminate_gx = " << terminate_gx <<
      ", terminate_gy = " << terminate_gy <<
      ", gx_session_id_suffix = " << user_session.gx_session_suffix() <<
      ", reason = " << reason <<
      std::endl;

    dpi::DiameterSession::GxTerminateRequest gx_terminate_request;
    if (not_found_charging_rule_names.has_value())
    {
      gx_terminate_request.not_found_charging_rule_names = *not_found_charging_rule_names;
    }

    if (gx_diameter_session_ && terminate_gx)
    {
      try
      {
        logger_->log("send diameter gx terminate");

        const auto [gx_session_suffix, gx_request_id] = user_session.generate_gx_request_id();

        dpi::DiameterSession::Request request;
        request.application_id = GX_APPLICATION_ID_;
        request.session_id_suffix = gx_session_suffix;
        request.request_id = gx_request_id;
        request.user_session_traits = *user_session.traits();
        fill_gx_stats_(gx_terminate_request, user_session);

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

        dpi::DiameterSession::GyRequest gy_terminate_request;
        fill_gy_request_(gy_terminate_request, user_session, false);

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

  bool
  Manager::update_session(
    const std::string& gx_session_id,
    bool update_gx,
    bool update_gy,
    const std::string& reason,
    const std::unordered_set<std::string>& install_charging_rule_names,
    const std::unordered_set<std::string>& remove_charging_rule_names)
  {
    auto session_suffix = get_session_suffix_(gx_session_id);
    auto user_session = user_session_storage_->get_user_session_by_gx_session_suffix(session_suffix);
    if (user_session)
    {
      return update_session(
        *user_session,
        update_gx,
        update_gy,
        reason,
        install_charging_rule_names,
        remove_charging_rule_names);
    }
    else
    {
      logger_->log(
        std::string("[ERROR] can't find session by suffix '") +
        session_suffix + "' on update");

      throw UnknownSession(std::string("Unknown session: ") + gx_session_id);
    }

    return false;
  }

  void
  Manager::update_session_async(
    const dpi::UserSessionPtr& user_session,
    bool update_gx,
    bool update_gy,
    const std::string& reason)
  {
    task_runner_->enqueue_task(std::make_shared<FunTask>(
      [this, user_session, update_gx, update_gy, reason]()
      {
        update_session(*user_session, update_gx, update_gy, reason);
      }
    ));
  }

  bool
  Manager::update_session(
    dpi::UserSession& user_session,
    bool update_gx,
    bool update_gy,
    const std::string& reason,
    const std::unordered_set<std::string>& install_charging_rule_names,
    const std::unordered_set<std::string>& remove_charging_rule_names,
    const EventTriggerArray& event_triggers)
  {
    std::cout << "Manager::update_session(): "
      "msisdn = " << user_session.traits()->msisdn <<
      ", update_gx = " << update_gx <<
      ", update_gy = " << update_gy <<
      std::endl;

    dpi::ConstPccConfigPtr pcc_config;                                                                                       

    if (pcc_config_provider_)
    {
      pcc_config = pcc_config_provider_->get_config();
    }

    if (!update_gx)
    {
      ChargingRuleNameSet new_install_charging_rule_names;
      ChargingRuleNameSet not_found_charging_rule_names;

      filter_charging_rules_(
        user_session,
        new_install_charging_rule_names,
        not_found_charging_rule_names,
        install_charging_rule_names);

      auto result_charging_rule_names = user_session.charging_rule_names();
      result_charging_rule_names.insert(
        new_install_charging_rule_names.begin(), new_install_charging_rule_names.end());
      for (const auto& remove_charging_rule_name : remove_charging_rule_names)
      {
        result_charging_rule_names.erase(remove_charging_rule_name);
      }

      if (user_session.traits()->msisdn == "79662660021")
      {
        result_charging_rule_names.emplace("MVNO_SBT_UNLIM");
      }

      user_session.set_charging_rule_names(result_charging_rule_names);

      if (result_charging_rule_names.empty())
      {
        // empty charging rules - drop session
        abort_session(
          user_session,
          true, //< terminate radius
          true, //< terminate gx
          true, //< terminate gy
          std::string("Empty charging rules after Gx update"));

        return false;
      }
    }
    else if (gx_diameter_session_)
    {
      dpi::DiameterSession::GxUpdateRequest gx_update_request;
      fill_gx_stats_(gx_update_request, user_session);
      gx_update_request.event_triggers = event_triggers;

      try
      {
        logger_->log("send diameter gx terminate");

        const auto [gx_session_id_suffix, gx_request_id] = user_session.generate_gx_request_id();

        dpi::DiameterSession::Request request;
        request.application_id = GX_APPLICATION_ID_;
        request.session_id_suffix = gx_session_id_suffix;
        request.request_id = gx_request_id;
        request.user_session_traits = *user_session.traits();

        // TODO: lock diameter exchange for session
        if (user_session.is_closed())
        {
          return false;
        }

        // TODO: lock diameter exchange for session
        if (user_session.is_closed())
        {
          return false;
        }

        dpi::DiameterSession::GxUpdateResponse response = gx_diameter_session_->send_gx_update(
          request,
          gx_update_request);

        if (response.result_code != 2001)
        {
          abort_session(
            user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            std::string("Gx update result code: ") + std::to_string(response.result_code));
          return false;
        }

        {
          std::ostringstream ostr;
          ostr << "diameter gx update response code: " << response.result_code;
          logger_->log(ostr.str());
        }

        auto result_charging_rule_names = user_session.charging_rule_names();

        // Apply passed charging rule changes before gx response charging rules.
        {
          ChargingRuleNameSet pre_install_charging_rule_names;
          ChargingRuleNameSet not_found_charging_rule_names;

          filter_charging_rules_(
            user_session,
            pre_install_charging_rule_names,
            not_found_charging_rule_names,
            install_charging_rule_names);

          result_charging_rule_names.insert(
            pre_install_charging_rule_names.begin(), pre_install_charging_rule_names.end());

          for (const auto& remove_charging_rule_name : remove_charging_rule_names)
          {
            result_charging_rule_names.erase(remove_charging_rule_name);
          }
        }

        // Apply response charging rule changes.
        ChargingRuleNameSet new_install_charging_rule_names;
        ChargingRuleNameSet not_found_charging_rule_names;

        filter_charging_rules_(
          user_session,
          new_install_charging_rule_names,
          not_found_charging_rule_names,
          response.install_charging_rule_names);

        result_charging_rule_names.insert(
          new_install_charging_rule_names.begin(), new_install_charging_rule_names.end());
        for (const auto& remove_charging_rule_name : response.remove_charging_rule_names)
        {
          result_charging_rule_names.erase(remove_charging_rule_name);
        }

        user_session.set_charging_rule_names(result_charging_rule_names);

        if (result_charging_rule_names.empty())
        {
          // empty charging rules - drop session
          abort_session(
            user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            std::string("Empty charging rules after Gx update"));

          return false;
        }
      }
      catch(const std::exception& ex)
      {
        logger_->log(std::string("send diameter gx update error: ") + ex.what());
      }
    }

    // Request Gy
    if (gy_diameter_session_ && update_gy)
    {
      try
      {
        logger_->log("send diameter gy terminate");

        DiameterSession::GyRequest gy_update_request; // To fix : use locally
        fill_gy_request_(gy_update_request, user_session, false);
        gy_update_request.reason = reason;

        // TODO: lock diameter exchange for session
        if (user_session.is_closed())
        {
          return false;
        }

        std::cout << "send_gy_update: usage_rating_groups.size = " << gy_update_request.usage_rating_groups.size() <<
          std::endl;

        dpi::DiameterSession::GyResponse gy_response = gy_diameter_session_->send_gy_update(
          gy_update_request);

        {
          std::ostringstream ostr;
          ostr << "diameter gy update response code: " << gy_response.result_code;
          logger_->log(ostr.str());
        }

        if (gy_response.result_code != 2001)
        {
          abort_session(
            user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            std::string("Gy update result code: ") + std::to_string(gy_response.result_code));
          return false;
        }

        bool any_success = false;
        for (const auto& rg : gy_response.rating_group_limits)
        {
          any_success = any_success || (rg.result_code == 2001);
        }

        /*
        if (!any_success)
        {
          abort_session(
            user_session,
            true, //< terminate radius
            true, //< terminate gx
            true, //< terminate gy
            "No success rating groups on Gy update");
          return false;
        }
        */

        fill_limits_by_gy_response_(user_session, gy_response, pcc_config);
      }
      catch(const std::exception& ex)
      {
        logger_->log(std::string("send diameter gy terminate error: ") + ex.what());
      }
    }

    return true;
  }
}
