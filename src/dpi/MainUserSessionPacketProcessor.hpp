#pragma once

#include "UserSessionPacketProcessor.hpp"
#include "UserStorage.hpp"

namespace dpi
{
  class MainUserSessionPacketProcessor: public UserSessionPacketProcessor
  {
  public:
    MainUserSessionPacketProcessor(
      UserStoragePtr user_storage,
      LoggerPtr event_logger);

    void
    set_session_rule_config(const SessionRuleConfig& session_rule_config);

    virtual PacketProcessingState
    process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
      const SessionKey& session_key,
      uint64_t packet_size) override;

  private:
    void check_user_state_(
      User& user,
      const SessionKey& trigger_session_key,
      uint32_t src_ip,
      uint32_t dst_ip,
      const Gears::Time& now);

    void log_event_(
      const std::string& event,
      const Gears::Time& now,
      uint32_t src_ip,
      uint32_t dst_ip);

  private:
    const UserStoragePtr user_storage_;
    const LoggerPtr event_logger_;
    Gears::GnuHashSet<SessionKey> recheck_state_session_keys_;
    SessionRuleConfig session_rule_config_;
  };
}
