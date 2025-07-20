#include <iostream>

#include <gears/StringManip.hpp>

#include "NetworkUtils.hpp"
#include "SessionKeyEvaluator.hpp"

namespace dpi
{
  namespace
  {
    using DomainSeparators = const Gears::Ascii::Char1Category<'.'>;
  }

  // SessionKeyEvaluator::SessionKeyRule impl
  SessionKeyEvaluator::SessionKeyRule::SessionKeyRule(
    unsigned int priority_val,
    const std::string& protocol_val,
    const IpMask& src_ip_mask_val,
    const std::optional<unsigned int>& src_port_val,
    const IpMask& dst_ip_mask_val,
    const std::optional<unsigned int>& dst_port_val,
    const SessionKey& session_key_val)
    : priority(priority_val),
      protocol(protocol_val),
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

  SessionKeyEvaluator::IpMask
  SessionKeyEvaluator::string_to_ip_mask(const std::string& ip_mask_string)
  {
    IpMask ip_mask;

    std::size_t slash_pos;
    std::size_t asterisk_pos;

    if (ip_mask_string == "*")
    {
      ip_mask.fixed_bits = 32;
      ip_mask.ip_mask = 0;
    }
    else if ((slash_pos = ip_mask_string.find('/')) != std::string::npos)
    {
      ip_mask.fixed_bits = std::atoi(ip_mask_string.substr(slash_pos + 1).c_str());
      ip_mask.ip_mask = string_to_ipv4_address(ip_mask_string.substr(0, slash_pos));
      ip_mask.ip_mask = ip_mask.ip_mask & (0xFFFFFFFF << (32 - ip_mask.fixed_bits));
    }
    else if (ip_mask_string.ends_with(".*"))
    {
      auto f_part = ip_mask_string.substr(0, ip_mask_string.size() - 2);
      Gears::StringManip::Splitter<DomainSeparators, true> splitter(f_part);
      Gears::SubString token;
      uint32_t result_ip = 0;
      unsigned int filled_parts = 0;
      for (int i = 0; i < 4; ++i)
      {
        unsigned char ip_part = 0;
        if (splitter.get_token(token))
        {
          if (!Gears::StringManip::str_to_int(token, ip_part))
          {
            throw InvalidParameter("");
          }

          ++filled_parts;
        }

        result_ip = (result_ip << 8) | ip_part;
      }

      ip_mask.fixed_bits = filled_parts * 8;
      ip_mask.ip_mask = result_ip;
    }

    return ip_mask;
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
    //std::cout << "add_rule_by_src_ip_" << std::endl;

    const IpMask& src_ip_mask = session_key_rule.src_ip_mask;
    if (src_ip_mask.fixed_bits == 0)
    {
      add_rule_by_dst_ip_(src_ip_index.no_ip_indexes, session_key_rule);
    }
    else
    {
      int use_index = (src_ip_mask.fixed_bits - 1) / 8;
      int fixed_bits_inside_byte = src_ip_mask.fixed_bits - use_index * 8;
      // 3 => 0xFFFFFFFF
      // 2 => 0xFFFFFF00
      // 1 => 0xFFFF0000
      // 0 => 0xFF000000
      std::unordered_map<uint32_t, DstIpSrcPortDstPortIndex>& ind = src_ip_index.ip_part_index[use_index];

      // to fix
      // create variations
      uint16_t max_var = 1 << (8 - fixed_bits_inside_byte);
      //std::cout << "add_rule_by_src_ip_: use_index = " << use_index << ", max_var = " << max_var << std::endl;
      for (uint16_t ip_var = 0; ip_var < max_var; ++ip_var)
      {
        uint32_t add_ip = ip_var | (src_ip_mask.ip_mask & (0xFFFFFFFF << (32 - src_ip_mask.fixed_bits)));
        //std::cout << "add_rule_by_src_ip_: ADD INTO PART #" << use_index << " IP=" << reversed_ipv4_address_to_string(add_ip) << std::endl;
        add_rule_by_dst_ip_(ind[add_ip], session_key_rule);
      }
    }
  }

  void
  SessionKeyEvaluator::add_rule_by_dst_ip_(
    DstIpSrcPortDstPortIndex& dst_ip_index,
    const SessionKeyRule& session_key_rule)
  {
    //std::cout << "add_rule_by_dst_ip_" << std::endl;

    const IpMask& dst_ip_mask = session_key_rule.dst_ip_mask;
    if (dst_ip_mask.fixed_bits == 0)
    {
      add_rule_by_src_port_(dst_ip_index.no_ip_indexes, session_key_rule);
    }
    else
    {
      int use_index = (dst_ip_mask.fixed_bits - 1) / 8;
      int fixed_bits_inside_byte = dst_ip_mask.fixed_bits - use_index * 8;
      // 3 => 0xFFFFFFFF
      // 2 => 0xFFFFFF00
      // 1 => 0xFFFF0000
      // 0 => 0xFF000000
      std::unordered_map<uint32_t, SrcPortDstPortIndex>& ind = dst_ip_index.ip_part_index[use_index];

      // to fix
      // create variations
      uint16_t max_var = 1 << (8 - fixed_bits_inside_byte);
      for (uint16_t ip_var = 0; ip_var < max_var; ++ip_var)
      {
        uint32_t add_ip = ip_var | (dst_ip_mask.ip_mask & (0xFFFFFFFF << (32 - dst_ip_mask.fixed_bits)));
        //std::cout << "add_rule_by_dst_ip_: ADD INTO PART #" << use_index << " IP=" << reversed_ipv4_address_to_string(add_ip) << std::endl;
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

    if (!flow_traits.protocol.empty())
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

    if (flow_traits.src_port.has_value())
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
