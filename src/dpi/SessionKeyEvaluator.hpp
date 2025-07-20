#pragma once

#include <memory>
#include <string>
#include <optional>
#include <unordered_map>
#include <vector>

#include "SessionKey.hpp"
#include "FlowTraits.hpp"

namespace dpi
{
  class SessionKeyEvaluator
  {
  public:
    struct IpMask
    {
      // by default match any ip address
      IpMask() {};
      IpMask(uint32_t ip_mask_val, unsigned int fixed_bits_val)
        : ip_mask(ip_mask_val),
          fixed_bits(fixed_bits_val)
      {};

      uint32_t ip_mask = 0;
      unsigned int fixed_bits = 0;
    };

    struct SessionKeyRule
    {
      SessionKeyRule() {};

      SessionKeyRule(
        unsigned int priority,
        const std::string& protocol,
        const IpMask& src_ip_mask,
        const std::optional<unsigned int>& src_port,
        const IpMask& dst_ip_mask,
        const std::optional<unsigned int>& dst_port,
        const SessionKey& session_key);

      unsigned int priority = 1;
      IpMask src_ip_mask;
      std::optional<unsigned int> src_port; // ?
      IpMask dst_ip_mask;
      std::optional<unsigned int> dst_port; // ?
      std::string protocol;
      SessionKey session_key;
    };

    static IpMask
    string_to_ip_mask(const std::string& string_ip_mask);

    /* look for conbinations 4 :
       src_ip, src_port, dst_ip, dst_port
       src_ip, src_port, dst_ip, 0
       src_ip,        0, dst_ip, dst_port
       src_ip,        0, dst_ip, 0

       4 * 3 (src_ip checks) * 3 (dst_ip checks) = 
    */

    void add_rule(const SessionKeyRule& session_key_rule);

    /*
      125.10.1.*
      125.10.*
     */
    SessionKey
    evaluate(const FlowTraits& flow_traits) const;

  private:
    template<typename InternalContainerType>
    struct IpIndex
    {
      InternalContainerType no_ip_indexes;
      // 0 -> first byte variations
      // 1 -> second byte variations
      // 2 -> 3 byte variations
      // 3 -> 4 byte variations
      std::unordered_map<uint32_t, InternalContainerType> ip_part_index[4];
    };

    struct SessionKeyFinalRule
    {
      unsigned int priority = 1;
      SessionKey session_key;
    };

    using SessionKeyFinalRuleArray = std::vector<SessionKeyFinalRule>;
    using DstPortIndex = std::unordered_map<uint16_t, SessionKeyFinalRuleArray>;
    using SrcPortDstPortIndex = std::unordered_map<uint16_t, DstPortIndex>;
    using DstIpSrcPortDstPortIndex = IpIndex<SrcPortDstPortIndex>;
    using SrcIpDstIpSrcPortDstPortIndex = IpIndex<DstIpSrcPortDstPortIndex>;
    using ProtocolIndex = std::unordered_map<std::string, SrcIpDstIpSrcPortDstPortIndex>;

  private:
    static void
    check_by_src_ip_(
      std::optional<SessionKeyFinalRule>& match_result,
      const SrcIpDstIpSrcPortDstPortIndex&,
      const FlowTraits& flow_traits);

    static void
    check_by_dst_ip_(
      std::optional<SessionKeyFinalRule>& match_result,
      const DstIpSrcPortDstPortIndex&,
      const FlowTraits& flow_traits);

    static void
    check_by_src_port_(
      std::optional<SessionKeyFinalRule>& match_result,
      const SrcPortDstPortIndex&,
      const FlowTraits& flow_traits);

    static void
    check_by_dst_port_(
      std::optional<SessionKeyFinalRule>& match_result,
      const DstPortIndex&,
      const FlowTraits& flow_traits);

    static void
    check_session_key_final_rules_(
      std::optional<SessionKeyFinalRule>& match_result,
      const SessionKeyFinalRuleArray&,
      const FlowTraits& flow_traits);

    // indexing
    static void
    add_rule_by_protocol_(
      ProtocolIndex& protocol_index,
      const SessionKeyRule& session_key_rule);

    static void
    add_rule_by_src_ip_(
      SrcIpDstIpSrcPortDstPortIndex& src_ip_index,
      const SessionKeyRule& session_key_rule);

    static void
    add_rule_by_dst_ip_(
      DstIpSrcPortDstPortIndex& src_ip_index,
      const SessionKeyRule& session_key_rule);

    static void
    add_rule_by_src_port_(
      SrcPortDstPortIndex& src_port_index,
      const SessionKeyRule& session_key_rule);

    static void
    add_rule_by_dst_port_(
      DstPortIndex& src_port_index,
      const SessionKeyRule& session_key_rule);

  private:
    ProtocolIndex protocol_index_;
  };

  using SessionKeyEvaluatorPtr = std::shared_ptr<SessionKeyEvaluator>;
}

