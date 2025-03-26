#pragma once

#include "UserSessionPacketProcessor.hpp"
#include "UserStorage.hpp"
#include "EventProcessor.hpp"
#include "ShapingManager.hpp"

namespace dpi
{
  // ShapedPacketsUserSessionPacketProcessor:
  // process only already shaped packets
  // packet can be shaped again
  class ShapedPacketsUserSessionPacketProcessor:
    public UserSessionPacketProcessor,
    public Gears::CompositeActiveObject
  {
  public:
    ShapedPacketsUserSessionPacketProcessor(
      UserStoragePtr user_storage,
      EventProcessorPtr event_processor);

    virtual PacketProcessingState
    process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      const FlowTraits& flow_traits,
      Direction direction,
      const SessionKey& session_key,
      uint64_t packet_size,
      const void* packet) override;
  };
}
