#pragma once

#include <memory>
#include <string>
#include <optional>
#include <mutex>

#include <gears/Time.hpp>
#include <gears/Hash.hpp>
#include <gears/HashTable.hpp>

#include "PacketProcessingState.hpp"

namespace dpi
{
  struct SessionKey
  {
    SessionKey();

    SessionKey(std::string traffic_type, std::string category_type);

    bool operator==(const SessionKey& right) const;

    unsigned long hash() const;

    const std::string traffic_type;
    const std::string category_type;

  protected:
    void calc_hash_();

  protected:
    unsigned long hash_;
  };

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

  private:
    struct BlockSessionHolder
    {
      Gears::Time block_timestamp;
    };

  private:
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

    // blocked sessions
    mutable std::mutex block_lock_;
    mutable Gears::HashTable<SessionKey, BlockSessionHolder> blocked_sessions_;
  };

  using UserPtr = std::shared_ptr<User>;
}

namespace dpi
{
  inline
  SessionKey::SessionKey()
    : hash_(0)
  {}

  inline
  SessionKey::SessionKey(std::string traffic_type_val, std::string category_type_val)
    : traffic_type(std::move(traffic_type_val)),
      category_type(std::move(category_type_val)),
      hash_(0)
  {
    calc_hash_();
  }

  inline
  bool SessionKey::operator==(const SessionKey& right) const
  {
    return traffic_type == right.traffic_type &&
      category_type == right.category_type;
  }

  inline unsigned long
  SessionKey::hash() const
  {
    return hash_;
  }

  inline void
  SessionKey::calc_hash_()
  {
    Gears::Murmur64Hash hasher(hash_);
    hash_add(hasher, traffic_type);
    hash_add(hasher, category_type);
  }

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
