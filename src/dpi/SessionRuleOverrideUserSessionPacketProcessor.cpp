#include <sstream>

#include "NetworkUtils.hpp"
#include "SessionRuleOverrideUserSessionPacketProcessor.hpp"

namespace dpi
{
  SessionRuleOverrideUserSessionPacketProcessor::SessionRuleOverrideUserSessionPacketProcessor(
    PccConfigProviderPtr pcc_config_provider)
    : pcc_config_provider_(std::move(pcc_config_provider))
  {}

  void
  SessionRuleOverrideUserSessionPacketProcessor::process_user_session_packet(
    PacketProcessingState& packet_processing_state,
    const Gears::Time& /*now*/,
    const UserPtr& /*user*/,
    const FlowTraits& /*flow_traits*/,
    Direction /*direction*/,
    const SessionKey& session_key,
    uint64_t /*packet_size*/,
    const void* /*packet*/
  )
  {
    ConstPccConfigPtr pcc_config = pcc_config_provider_->get_config();
    if (pcc_config)
    {
      auto session_key_rule_it = pcc_config->session_rule_by_session_key.find(session_key);
      if (session_key_rule_it != pcc_config->session_rule_by_session_key.end())
      {
        const PccConfig::SessionKeyRule& session_key_rule = session_key_rule_it->second;
        if (session_key_rule.allow_traffic)
        {
          //std::cout << "Unblock by session rule: " << session_key.to_string() << std::endl;
          packet_processing_state.block_packet = false;
          packet_processing_state.shaped = false;
        }
      }
    }
  }
}
