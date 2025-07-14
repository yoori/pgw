#include <iostream>

#include "NetworkUtils.hpp"
#include "SessionKeyEvaluator.hpp"

namespace dpi
{
  // SessionKeyEvaluator::SessionKeyRule impl
  SessionKeyEvaluator::SessionKeyRule::SessionKeyRule(
    unsigned int priority_val,
    const IpMask& src_ip_mask_val,
    const std::optional<unsigned int>& src_port_val,
    const IpMask& dst_ip_mask_val,
    const std::optional<unsigned int>& dst_port_val,
    const SessionKey& session_key_val)
    : priority(priority_val),
      src_ip_mask(src_ip_mask_val),
      src_port(src_port_val),
      dst_ip_mask(dst_ip_mask_val),
      dst_port(dst_port_val),
      session_key(session_key_val)
  {}

  // SessionKeyEvaluator impl
  void
  SessionKeyEvaluator::add_rule(const SessionKeyRule& session_key_rule)
  {
    add_rule_by_protocol_(protocol_index_, session_key_rule);
  }

  void
  SessionKeyEvaluator::add_rule_by_protocol_(
    ProtocolIndex& protocol_index,
    const SessionKeyRule& session_key_rule)
  {
    add_rule_by_src_ip_(protocol_index[session_key_rule.protocol], session_key_rule);
  }

  void
  SessionKeyEvaluator::add_rule_by_src_ip_(
    SrcIpDstIpSrcPortDstPortIndex& src_ip_index,
    const SessionKeyRule& session_key_rule)
  {
  }

  void
  SessionKeyEvaluator::add_rule_by_dst_ip_(
    DstIpSrcPortDstPortIndex& dst_ip_index,
    const SessionKeyRule& session_key_rule)
  {
    const IpMask& dst_ip_mask = session_key_rule.dst_ip_mask;
    if (dst_ip_mask.fixed_bits == 0)
    {
      add_rule_by_src_port_(dst_ip_index.no_ip_indexes, session_key_rule);
    }
    else
    {
      int use_index = (dst_ip_mask.fixed_bits - 1) / 8;
      int var_bits_inside_byte = dst_ip_mask.fixed_bits - use_index * 8;
      // 3 => 0xFFFFFFFF
      // 2 => 0xFFFFFF00
      // 1 => 0xFFFF0000
      // 0 => 0xFF000000
      std::unordered_map<uint32_t, SrcPortDstPortIndex>& ind = dst_ip_index.ip_part_index[use_index];

      // to fix
      // create variations
      uint8_t max_var = 1 << var_bits_inside_byte;
      for (uint8_t ip_var = 0; ip_var < max_var; ++ip_var)
      {
        uint32_t add_ip = ip_var << ((3 - use_index) * 8);
        std::cout << "ADD INTO PART #" << use_index << " IP=" << ipv4_address_to_string(add_ip) << std::endl;
        add_rule_by_src_port_(ind[add_ip], session_key_rule);
      }
    }
  }

  void
  SessionKeyEvaluator::add_rule_by_src_port_(
    SrcPortDstPortIndex& src_port_index,
    const SessionKeyRule& session_key_rule)
  {
    if (session_key_rule.src_port.has_value())
    {
      add_rule_by_dst_port_(src_port_index[*session_key_rule.src_port], session_key_rule);
    }
    else
    {
      add_rule_by_dst_port_(src_port_index[0], session_key_rule);
    }
  }

  void
  SessionKeyEvaluator::add_rule_by_dst_port_(
    DstPortIndex& dst_port_index,
    const SessionKeyRule& session_key_rule)
  {
    SessionKeyFinalRule session_key_final_rule;
    session_key_final_rule.priority = session_key_rule.priority;
    session_key_final_rule.session_key = session_key_rule.session_key;

    if (session_key_rule.dst_port.has_value())
    {
      dst_port_index[*session_key_rule.dst_port].emplace_back(session_key_final_rule);
    }
    else
    {
      dst_port_index[0].emplace_back(session_key_final_rule);
    }
  }

  SessionKey
  SessionKeyEvaluator::evaluate(const FlowTraits& flow_traits) const
  {
    std::optional<SessionKeyFinalRule> match_result;

    {
      auto protocol_it = protocol_index_.find(flow_traits.protocol);
      if (protocol_it != protocol_index_.end())
      {
        check_by_src_ip_(match_result, protocol_it->second, flow_traits);
      }
    }

    {
      auto protocol_it = protocol_index_.find(std::string());
      if (protocol_it != protocol_index_.end())
      {
        check_by_src_ip_(match_result, protocol_it->second, flow_traits);
      }
    }

    if (match_result.has_value())
    {
      return match_result->session_key;
    }

    return SessionKey();
  }

  void
  SessionKeyEvaluator::check_by_src_ip_(
    std::optional<SessionKeyFinalRule>& match_result,
    const SrcIpDstIpSrcPortDstPortIndex& src_ip_index,
    const FlowTraits& flow_traits)
  {
    check_by_dst_ip_(match_result, src_ip_index.no_ip_indexes, flow_traits);

    uint32_t cur_mask = 0xFFFFFFFF;
    for (int i = 3; i >= 0; --i)
    {
      // 3 => 0xFFFFFFFF
      // 2 => 0xFFFFFF00
      // 1 => 0xFFFF0000
      // 0 => 0xFF000000
      const uint32_t p1 = flow_traits.src_ip & cur_mask;
      const auto part_it = src_ip_index.ip_part_index[i].find(p1);
      if (part_it != src_ip_index.ip_part_index[i].end())
      {
        check_by_dst_ip_(match_result, part_it->second, flow_traits);
      }

      cur_mask = cur_mask << 8;
    }
  }

  void
  SessionKeyEvaluator::check_by_dst_ip_(
    std::optional<SessionKeyFinalRule>& match_result,
    const DstIpSrcPortDstPortIndex& dst_ip_index,
    const FlowTraits& flow_traits)
  {
    check_by_src_port_(match_result, dst_ip_index.no_ip_indexes, flow_traits);

    uint32_t cur_mask = 0xFFFFFFFF;
    for (int i = 3; i >= 0; --i)
    {
      // 3 => 0xFFFFFFFF
      // 2 => 0xFFFFFF00
      // 1 => 0xFFFF0000
      // 0 => 0xFF000000
      const uint32_t p1 = flow_traits.dst_ip & cur_mask;
      const auto part_it = dst_ip_index.ip_part_index[i].find(p1);
      if (part_it != dst_ip_index.ip_part_index[i].end())
      {
        check_by_src_port_(match_result, part_it->second, flow_traits);
      }

      cur_mask = cur_mask << 8;
    }
  }

  void
  SessionKeyEvaluator::check_by_src_port_(
    std::optional<SessionKeyFinalRule>& match_result,
    const SrcPortDstPortIndex& src_port_dst_port_index,
    const FlowTraits& flow_traits)
  {
    {
      auto port_it = src_port_dst_port_index.find(0);
      if (port_it != src_port_dst_port_index.end())
      {
        check_by_dst_port_(match_result, port_it->second, flow_traits);
      }
    }

    if (flow_traits.dst_port.has_value())
    {
      auto port_it = src_port_dst_port_index.find(*flow_traits.src_port);
      if (port_it != src_port_dst_port_index.end())
      {
        check_by_dst_port_(match_result, port_it->second, flow_traits);
      }
    }
  }

  void
  SessionKeyEvaluator::check_by_dst_port_(
    std::optional<SessionKeyFinalRule>& match_result,
    const DstPortIndex& dst_port_index,
    const FlowTraits& flow_traits)
  {
    {
      auto port_it = dst_port_index.find(0);
      if (port_it != dst_port_index.end())
      {
        check_session_key_final_rules_(match_result, port_it->second, flow_traits);
      }
    }

    if (flow_traits.dst_port.has_value())
    {
      auto port_it = dst_port_index.find(*flow_traits.dst_port);
      if (port_it != dst_port_index.end())
      {
        check_session_key_final_rules_(match_result, port_it->second, flow_traits);
      }
    }
  }

  void
  SessionKeyEvaluator::check_session_key_final_rules_(
    std::optional<SessionKeyFinalRule>& match_result,
    const SessionKeyFinalRuleArray& session_key_rules,
    const FlowTraits& flow_traits)
  {
    for (const auto& sk : session_key_rules)
    {
      if (!match_result.has_value() || sk.priority > match_result->priority)
      {
        match_result = sk;
      }
    }
  }
}
