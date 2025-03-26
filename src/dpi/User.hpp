#pragma once

#include <memory>
#include <string>
#include <optional>
#include <mutex>

#include <gears/Time.hpp>
#include <gears/Hash.hpp>
#include <gears/HashTable.hpp>

#include "PacketProcessingState.hpp"
#include "SessionKey.hpp"

namespace dpi
{
  struct SessionRuleConfig
  {
    struct SessionTypeRule
    {
      Gears::Time close_timeout; //< Period between packets after that session will be closed.
    };

    Gears::Time clear_closed_sessions_timeout;
    SessionTypeRule default_rule;
    Gears::HashTable<SessionKey, SessionTypeRule> session_rules;
  };

  using SessionRuleConfigPtr = std::shared_ptr<SessionRuleConfig>;

  struct User
  {
  public:
    struct Session
    {
      Session(const SessionKey& session_key_val)
        : session_key(session_key_val)
      {}

      const SessionKey session_key;
      Gears::Time first_packet_timestamp;
      Gears::Time last_packet_timestamp;
    };

    using SessionPtr = std::shared_ptr<Session>;

    struct TrafficState
    {
      TrafficState();
      TrafficState(unsigned long packets_val, unsigned long size);
      TrafficState& operator+=(const TrafficState& right);

      unsigned long packets = 0;
      unsigned long size = 0;
    };

    using TrafficStatePtr = std::shared_ptr<TrafficState>;

  public:
    User(std::string msisdn, uint32_t ip = 0);

    const std::string& msisdn() const;

    void set_ip(uint32_t ip);

    uint32_t ip() const;

    PacketProcessingState process_packet(
      const SessionRuleConfig& session_rule_config,
      const SessionKey& session_key,
      const Gears::Time& time,
      unsigned long size);

    void clear_expired_sessions(
      const SessionRuleConfig& session_rule_config,
      const Gears::Time& now);

    std::string to_string() const;

    std::string to_json_string() const;

    std::optional<Gears::Time> session_open_timestamp(
      const SessionKey& session_key) const;

    void session_block(
      const SessionKey& key, const Gears::Time& block_timestamp);

    bool is_session_blocked(
      const SessionKey& key, const Gears::Time& now) const;

    void set_shaping(
      const std::vector<SessionKey>& session_keys,
      unsigned long bytes_limit);

    bool is_session_blocked_by_equal_key_i_(
      const SessionKey& key, const Gears::Time& now) const;

  private:
    struct BlockSessionHolder
    {
      Gears::Time block_timestamp;
    };

    struct ShapeGroup
    {
      unsigned long bytes_limit = 0;
      Gears::Time last_timestamp;
      unsigned long bytes = 0;
      unsigned long deferred_bytes = 0;
    };

    using ShapeGroupPtr = std::shared_ptr<ShapeGroup>;

  private:
    // return true if need to shape
    bool process_shaping_i_(
      const Gears::Time& now,
      const SessionKey& session_key,
      unsigned long size);

    bool is_session_blocked_i_(
      const SessionKey& key, const Gears::Time& now) const;

    void clear_expired_sessions_i_(
      const SessionRuleConfig& session_rule_config,
      const Gears::Time& now);

    static const SessionRuleConfig::SessionTypeRule&
    get_session_rule_(
      const SessionRuleConfig& session_rule_config,
      const SessionKey& session_key);

  private:
    mutable std::mutex lock_;
    const std::string msisdn_;
    uint32_t ip_;
    std::unordered_map<std::string, TrafficStatePtr> traffic_states_;

    // opened sessions
    Gears::HashTable<SessionKey, TrafficState> traffic_sums_;
    Gears::HashTable<SessionKey, SessionPtr> opened_sessions_;
    // closed sessions
    std::map<Gears::Time, SessionPtr> closed_sessions_;
    Gears::HashTable<SessionKey, std::vector<ShapeGroupPtr>> shape_groups_;

    // blocked sessions
    mutable std::mutex block_lock_;
    mutable Gears::HashTable<SessionKey, BlockSessionHolder> blocked_sessions_;
  };

  using UserPtr = std::shared_ptr<User>;
}

namespace dpi
{
  // User inlines
  inline std::optional<Gears::Time>
  User::session_open_timestamp(const SessionKey& session_key) const
  {
    auto session_it = opened_sessions_.find(session_key);
    if (session_it == opened_sessions_.end())
    {
      return std::nullopt;
    }

    return session_it->second->first_packet_timestamp;
  }

  // User::TrafficState inlines
  inline
  User::TrafficState::TrafficState()
  {}

  inline
  User::TrafficState::TrafficState(unsigned long packets_val, unsigned long size_val)
    : packets(packets_val), size(size_val)
  {}

  inline User::TrafficState&
  User::TrafficState::operator+=(const User::TrafficState& right)
  {
    packets += right.packets;
    size += right.size;
    return *this;
  }
}
