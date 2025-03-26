#include <sstream>

#include "NetworkUtils.hpp"
#include "MainUserSessionPacketProcessor.hpp"

namespace dpi
{
  MainUserSessionPacketProcessor::MainUserSessionPacketProcessor(
    UserStoragePtr user_storage,
    EventProcessorPtr event_processor)
    : user_storage_(std::move(user_storage)),
      event_processor_(std::move(event_processor))
  {
    recheck_state_session_keys_.emplace(SessionKey("rdp", std::string()));
    recheck_state_session_keys_.emplace(SessionKey("anydesk", std::string()));
    recheck_state_session_keys_.emplace(SessionKey("telegram_voip", std::string()));
    recheck_state_session_keys_.emplace(SessionKey("tls", "sber-online"));
    recheck_state_session_keys_.emplace(SessionKey("tls", "gosuslugi"));
    recheck_state_session_keys_.emplace(SessionKey("tls", "alfabank-online"));
    recheck_state_session_keys_.emplace(SessionKey("tls", "anydesk"));
    recheck_state_session_keys_.emplace(SessionKey("", "fishing"));
  }

  void
  MainUserSessionPacketProcessor::set_session_rule_config(
    const SessionRuleConfig& session_rule_config)
  {
    session_rule_config_ = session_rule_config;
  }

  void
  MainUserSessionPacketProcessor::process_user_session_packet(
    PacketProcessingState& packet_processing_state,
    const Gears::Time& now,
    const UserPtr& user,
    const FlowTraits& flow_traits,
    Direction /*direction*/,
    const SessionKey& session_key,
    uint64_t packet_size,
    const void* packet)
  {
    {
      PacketProcessingState local_packet_processing_state = user->process_packet(
        session_rule_config_,
        session_key,
        now,
        packet_size);

      packet_processing_state += local_packet_processing_state;
    }

    if (session_key.category_type() == "fishing")
    {
      // fishing event
      if (!process_event_(
            session_key.category_type(),
            now,
            flow_traits.src_ip,
            flow_traits.dst_ip))
      {
        packet_processing_state.block_packet = true;
      }
    }

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
        packet_processing_state.opened_new_session = true;

        if (recheck_state_session_keys_.find(session_key) != recheck_state_session_keys_.end() ||
          recheck_state_session_keys_.find(SessionKey(std::string(), session_key.category_type())) !=
            recheck_state_session_keys_.end())
        {
          bool local_send_packet = check_user_state_(
            *user,
            session_key,
            flow_traits.src_ip,
            flow_traits.dst_ip,
            now);
          if (!local_send_packet)
          {
            packet_processing_state.block_packet = true;
          }
        }
      }
    }
  }

  struct NamedSessionKey
  {
    SessionKey session_key;
    std::string name;
  };

  bool MainUserSessionPacketProcessor::check_user_state_(
    User& user,
    const SessionKey& trigger_session_key,
    uint32_t src_ip,
    uint32_t dst_ip,
    const Gears::Time& now)
  {
    bool send_packet = true;

    // if now opened telegram call
    if (trigger_session_key.traffic_type() == "telegram_voip")
    {
      auto ts = user.session_open_timestamp(trigger_session_key);
      if (ts.has_value() && *ts == now)
      {
        bool local_send_packet = process_event_(
          trigger_session_key.traffic_type() + " open", now, src_ip, dst_ip);
        send_packet = send_packet && local_send_packet;
      }
    }

    if (trigger_session_key.traffic_type() == "rdp" ||
      trigger_session_key.traffic_type() == "anydesk" ||
      (trigger_session_key.traffic_type() == "tls" && trigger_session_key.category_type() == "anydesk"))
    {
      std::cout << "AnyDesk !" << std::endl;
      auto ts = user.session_open_timestamp(trigger_session_key);
      if (ts.has_value() && *ts == now)
      {
        bool local_send_packet = process_event_(
          "remote-control open", now, src_ip, dst_ip);
        send_packet = send_packet && local_send_packet;
      }
    }

    if (trigger_session_key.traffic_type() == "tls" && (
      trigger_session_key.category_type() == "sber-online" ||
      trigger_session_key.category_type() == "alfabank-online" ||
      trigger_session_key.category_type() == "gosuslugi"))
    {
      auto ts = user.session_open_timestamp(trigger_session_key);
      if (ts.has_value() && *ts == now)
      {
        // check that telegram session is opened
        NamedSessionKey CHECK_SESSIONS[] = {
          { SessionKey("telegram_voip", ""), "telegram_voip" },
          { SessionKey("rdp", ""), "remote-control" },
          { SessionKey("anydesk", ""), "remote-control" },
          { SessionKey("tls", "anydesk"), "remote-control" }
        };

        for (int check_i = 0; check_i < sizeof(CHECK_SESSIONS) / sizeof(CHECK_SESSIONS[0]); ++check_i)
        {
          auto check_ts = user.session_open_timestamp(CHECK_SESSIONS[check_i].session_key);
          if (check_ts.has_value())
          {
            bool local_send_packet = process_event_(
              trigger_session_key.category_type() + " open on " + CHECK_SESSIONS[check_i].name,
              now,
              src_ip,
              dst_ip);
            send_packet = send_packet && local_send_packet;
          }
          else
          {
            bool local_send_packet = process_event_(
              trigger_session_key.category_type() + " open", now, src_ip, dst_ip);
            send_packet = send_packet && local_send_packet;
          }
        }
      }
    }

    return send_packet;
  }

  bool MainUserSessionPacketProcessor::process_event_(
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
    ostr << ", destination ip = " << ipv4_address_to_string(dst_ip);

    return event_processor_->process_event(user, event, ostr.str());
  }
}
