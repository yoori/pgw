#include <sstream>

#include "NetworkUtils.hpp"
#include "MainUserSessionPacketProcessor.hpp"

namespace dpi
{
  MainUserSessionPacketProcessor::MainUserSessionPacketProcessor(
    UserStoragePtr user_storage,
    LoggerPtr event_logger)
    : user_storage_(std::move(user_storage)),
      event_logger_(std::move(event_logger))
  {
    recheck_state_session_keys_.emplace(SessionKey("rdp", std::string()));
    recheck_state_session_keys_.emplace(SessionKey("telegram_voip", std::string()));
    recheck_state_session_keys_.emplace(SessionKey("tls", "sber-online"));
    recheck_state_session_keys_.emplace(SessionKey("tls", "gosuslugi"));
    recheck_state_session_keys_.emplace(SessionKey("tls", "alfabank-online"));
  }

  void
  MainUserSessionPacketProcessor::set_session_rule_config(
    const SessionRuleConfig& session_rule_config)
  {
    session_rule_config_ = session_rule_config;
  }

  PacketProcessingState
  MainUserSessionPacketProcessor::process_user_session_packet(
    const Gears::Time& now,
    const UserPtr& user,
    uint32_t src_ip,
    uint32_t dst_ip,
    const SessionKey& session_key,
    uint64_t packet_size)
  {
    PacketProcessingState packet_processing_state = user->process_packet(
      session_rule_config_,
      session_key,
      now,
      packet_size);

    // Check possible state changes
    if (!user->msisdn().empty())
    {
      /*
      std::cout << "XXX packet: traffic_type = " << session_key.traffic_type <<
        ", category_type = " << session_key.category_type <<
        ", src = " << ipv4_address_to_string(src_ip) <<
        ", dst = " << ipv4_address_to_string(dst_ip) <<
        std::endl;
      */

      if (packet_processing_state.opened_new_session)
        //< check events state change only if new session opened
      {
        if (recheck_state_session_keys_.find(session_key) != recheck_state_session_keys_.end() ||
          recheck_state_session_keys_.find(SessionKey(std::string(), session_key.category_type)) !=
            recheck_state_session_keys_.end())
        {
          check_user_state_(*user, session_key, src_ip, dst_ip, now);
        }
      }
    }

    return packet_processing_state;
  }

  void MainUserSessionPacketProcessor::check_user_state_(
    User& user,
    const SessionKey& trigger_session_key,
    uint32_t src_ip,
    uint32_t dst_ip,
    const Gears::Time& now)
  {
    // if now opened telegram call
    if (trigger_session_key.traffic_type == "telegram_voip" ||
      trigger_session_key.traffic_type == "rdp")
    {
      auto ts = user.session_open_timestamp(trigger_session_key);
      if (ts.has_value() && *ts == now)
      {
        log_event_(trigger_session_key.traffic_type, now, src_ip, dst_ip);
      }
    }

    if (trigger_session_key.traffic_type == "tls" && (
      trigger_session_key.category_type == "sber-online" ||
      trigger_session_key.category_type == "alfabank-online" ||
      trigger_session_key.category_type == "gosuslugi"))
    {
      auto ts = user.session_open_timestamp(trigger_session_key);
      if (ts.has_value() && *ts == now)
      {
        // check that telegram session is opened
        const char* CHECK_SESSIONS[] = {
          "telegram_voip",
          "rdp"
        };

        for (int check_i = 0; check_i < sizeof(CHECK_SESSIONS) / sizeof(CHECK_SESSIONS[0]); ++check_i)
        {
          auto check_ts = user.session_open_timestamp(SessionKey(CHECK_SESSIONS[check_i], std::string()));
          if (check_ts.has_value())
          {
            log_event_(
              trigger_session_key.category_type + " open on " + CHECK_SESSIONS[check_i],
              now,
              src_ip,
              dst_ip);
          }
          else
          {
            log_event_(trigger_session_key.category_type + " open", now, src_ip, dst_ip);
          }
        }
      }
    }
  }

  void MainUserSessionPacketProcessor::log_event_(
    const std::string& event,
    const Gears::Time& now,
    uint32_t src_ip,
    uint32_t dst_ip
    )
  {
    UserPtr user = user_storage_->get_user_by_ip(src_ip, now);

    if (!user)
    {
      user = user_storage_->get_user_by_ip(dst_ip, now);
      if (user)
      {
        std::swap(src_ip, dst_ip);
      }
    }

    if (!user)
    {
      user = std::make_shared<User>(std::string());
      user->set_ip(src_ip);
    }

    std::ostringstream ostr;
    ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] [sber-telecom] EVENT '" << event << "': " <<
      user->to_string() << ", destination ip = " << ipv4_address_to_string(dst_ip) <<
      std::endl;
    event_logger_->log(ostr.str());
  }
}
