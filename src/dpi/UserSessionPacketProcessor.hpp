#pragma once

#include "User.hpp"
#include "PacketProcessingState.hpp"
#include "FlowTraits.hpp"

namespace dpi
{
  class UserSessionPacketProcessor
  {
  public:
    enum Direction
    {
      D_NONE = 0,
      D_OUTPUT,
      D_INPUT
    };

    virtual void process_user_session_packet(
      PacketProcessingState& packet_processing_state,
      const Gears::Time& time,
      const UserPtr& user,
      const FlowTraits& flow_traits,
      Direction direction,
      const SessionKey& session_key,
      uint64_t packet_size,
      const void* packet) = 0;
  };

  using UserSessionPacketProcessorPtr = std::shared_ptr<UserSessionPacketProcessor>;

  class CompositeUserSessionPacketProcessor: public UserSessionPacketProcessor
  {
  public:
    CompositeUserSessionPacketProcessor();

    void add_child_object(UserSessionPacketProcessorPtr);

    virtual void process_user_session_packet(
      PacketProcessingState& packet_processing_state,
      const Gears::Time& time,
      const UserPtr& user,
      const FlowTraits& flow_traits,
      Direction direction,
      const SessionKey& session_key,
      uint64_t packet_size,
      const void* packet) override;

  private:
    std::vector<UserSessionPacketProcessorPtr> childs_;
  };

  const std::string&
  direction_to_string(UserSessionPacketProcessor::Direction direction);
}
