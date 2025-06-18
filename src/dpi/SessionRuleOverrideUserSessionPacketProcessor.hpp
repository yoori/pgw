#pragma once

#include "UserSessionPacketProcessor.hpp"
#include "UserStorage.hpp"
#include "UserSessionStorage.hpp"
#include "EventProcessor.hpp"
#include "ShapingManager.hpp"
#include "PccConfigProvider.hpp"

namespace dpi
{
  class SessionRuleOverrideUserSessionPacketProcessor:
    public UserSessionPacketProcessor,
    public Gears::CompositeActiveObject
  {
  public:
    SessionRuleOverrideUserSessionPacketProcessor(
      PccConfigProviderPtr pcc_config_provider);

    virtual void
    process_user_session_packet(
      PacketProcessingState& packet_processing_state,
      const Gears::Time& time,
      const UserPtr& user,
      const FlowTraits& flow_traits,
      Direction direction,
      const SessionKey& session_key,
      uint64_t packet_size,
      const void* packet) override;

  private:
    const PccConfigProviderPtr pcc_config_provider_;
  };
}
