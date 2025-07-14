#include "UserSessionPacketProcessor.hpp"

namespace dpi
{
  namespace
  {
    const std::string DIRECTION_NONE_STR("none");
    const std::string DIRECTION_OUTPUT_STR("output");
    const std::string DIRECTION_INPUT_STR("input");
  };

  const std::string&
  direction_to_string(Direction direction)
  {
    if (direction == Direction::D_OUTPUT)
    {
      return DIRECTION_OUTPUT_STR;
    }

    if (direction == Direction::D_INPUT)
    {
      return DIRECTION_INPUT_STR;
    }

    return DIRECTION_NONE_STR;
  }

  CompositeUserSessionPacketProcessor::CompositeUserSessionPacketProcessor()
  {}

  void
  CompositeUserSessionPacketProcessor::add_child_object(
    UserSessionPacketProcessorPtr child)
  {
    childs_.emplace_back(std::move(child));
  }

  void
  CompositeUserSessionPacketProcessor::process_user_session_packet(
    PacketProcessingState& packet_processing_state,
    const Gears::Time& time,
    const UserPtr& user,
    const FlowTraits& flow_traits,
    Direction direction,
    const SessionKey& session_key,
    uint64_t packet_size,
    const void* packet)
  {
    for (auto& child : childs_)
    {
      child->process_user_session_packet(
        packet_processing_state,
        time,
        user,
        flow_traits,
        direction,
        session_key,
        packet_size,
        packet);
    }
  }
}
