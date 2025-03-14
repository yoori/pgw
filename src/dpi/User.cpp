#include <jsoncons/json.hpp>

#include "NetworkUtils.hpp"

#include "User.hpp"

namespace dpi
{
  // User impl.
  User::User(std::string msisdn)
    : msisdn_(std::move(msisdn))
  {}

  void
  User::set_ip(uint32_t ip)
  {
    std::unique_lock lock{lock_};
    ip_ = ip;
  }

  uint32_t User::ip() const
  {
    return ip_;
  }

  const std::string&
  User::msisdn() const
  {
    return msisdn_;
  }

  std::string
  User::to_string() const
  {
    uint32_t ip;

    {
      std::unique_lock lock{lock_};
      ip = ip_;
    }

    return std::string("{msisdn = ") + msisdn_ +
      ", ip = " + ipv4_address_to_string(ip) + "}";
  }

  std::string
  User::to_json_string() const
  {
    jsoncons::json result_json;

    {
      std::unique_lock lock{lock_};

      if (!msisdn_.empty())
      {
        result_json["msisdn"] = msisdn_;
      }

      if (ip_ != 0)
      {
        result_json["ip"] = ipv4_address_to_string(ip_);
      }

      std::vector<jsoncons::json> traffic_state_arr;
      for (const auto& [session_key, traffic_sum] : traffic_sums_)
      {
        jsoncons::json traffic_state;
        traffic_state["traffic_type"] = session_key.traffic_type;
        if (!session_key.category_type.empty())
        {
          traffic_state["category"] = session_key.category_type;
        }
        traffic_state["packets"] = traffic_sum.packets;
        traffic_state["size"] = traffic_sum.size;
        traffic_state_arr.emplace_back(std::move(traffic_state));
      }
      result_json["amounts"] = traffic_state_arr;

      std::vector<jsoncons::json> opened_sessions_arr;
      for (const auto& [session_key, session] : opened_sessions_)
      {
        jsoncons::json opened_session;
        opened_session["traffic_type"] = session_key.traffic_type;
        if (!session_key.category_type.empty())
        {
          opened_session["category"] = session_key.category_type;
        }
        opened_session["first_packet_timestamp"] = session->first_packet_timestamp.gm_ft();
        opened_session["last_packet_timestamp"] = session->last_packet_timestamp.gm_ft();
        opened_sessions_arr.emplace_back(std::move(opened_session));
      }
      result_json["opened_sessions"] = opened_sessions_arr;

      // fill closed sessions
      std::vector<jsoncons::json> closed_sessions_arr;
      for (const auto& [close_timestamp, session] : closed_sessions_)
      {
        jsoncons::json closed_session;
        closed_session["traffic_type"] = session->session_key.traffic_type;
        if (!session->session_key.category_type.empty())
        {
          closed_session["category"] = session->session_key.category_type;
        }
        closed_session["first_packet_timestamp"] = session->first_packet_timestamp.gm_ft();
        closed_session["last_packet_timestamp"] = session->last_packet_timestamp.gm_ft();
        closed_sessions_arr.emplace_back(std::move(closed_session));
      }
      result_json["closed_sessions"] = closed_sessions_arr;
    }

    jsoncons::json_options json_print_options;
    json_print_options.escape_all_non_ascii(false);
    std::ostringstream ostr;
    ostr << jsoncons::json_printable<jsoncons::json>(
      result_json, json_print_options, jsoncons::indenting::indent);
    return ostr.str();
  }

  const SessionRuleConfig::SessionTypeRule&
  User::get_session_rule_(
    const SessionRuleConfig& session_rule_config,
    const SessionKey& session_key)
  {
    auto rule_it = session_rule_config.session_rules.find(session_key);
    if (rule_it != session_rule_config.session_rules.end())
    {
      return rule_it->second;
    }

    rule_it = session_rule_config.session_rules.find(
      SessionKey(session_key.traffic_type, std::string()));
    if (rule_it != session_rule_config.session_rules.end())
    {
      return rule_it->second;
    }

    return session_rule_config.default_rule;
  }

  void User::clear_expired_sessions(
    const SessionRuleConfig& session_rule_config,
    const Gears::Time& now)
  {
    std::unique_lock lock{lock_};
    clear_expired_sessions_i_(session_rule_config, now);
  }

  void User::clear_expired_sessions_i_(
    const SessionRuleConfig& session_rule_config,
    const Gears::Time& now)
  {
    // close opened sessions by timeout
    for (auto it = opened_sessions_.begin(); it != opened_sessions_.end(); )
    {
      const SessionRuleConfig::SessionTypeRule& session_rule =
        get_session_rule_(session_rule_config, it->second->session_key);

      if (it->second->last_packet_timestamp + session_rule.close_timeout < now)
      {
        // close session and open new.
        closed_sessions_.emplace(it->second->last_packet_timestamp, it->second);
        it = opened_sessions_.erase(it);
      }
      else
      {
        ++it;
      }
    }

    // clear closed sessions
    const auto expire_time = now - session_rule_config.clear_closed_sessions_timeout;
    while (!closed_sessions_.empty() &&
      closed_sessions_.begin()->first < expire_time)
    {
      closed_sessions_.erase(closed_sessions_.begin());
    }
  }

  bool User::process_packet(
    const SessionRuleConfig& session_rule_config,
    const SessionKey& session_key,
    const Gears::Time& now,
    unsigned long size)
  {
    const SessionRuleConfig::SessionTypeRule& session_rule =
      get_session_rule_(session_rule_config, session_key);

    bool opened_new_session = false;
    SessionPtr del_session;

    {
      std::unique_lock lock{lock_};

      clear_expired_sessions_i_(session_rule_config, now);

      // try to continue opened session
      auto& session = opened_sessions_[session_key];

      if (session && session->last_packet_timestamp + session_rule.close_timeout < now)
      {
        // close session and open new.
        closed_sessions_.emplace(session->last_packet_timestamp, session);
        session.swap(del_session);
      }

      if (!session)
      {
        //std::cout << "CREATE SESSION FOR traffic_type = " << session_key.traffic_type <<
        //  ", category_type = " << session_key.category_type << std::endl;
        session = std::make_shared<Session>(session_key);
        session->first_packet_timestamp = now;
        opened_new_session = true;
      }

      session->last_packet_timestamp = now;

      traffic_sums_[session_key] += TrafficState(1, size);
    }

    return opened_new_session;
  }
}
