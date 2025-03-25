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
  direction_to_string(UserSessionPacketProcessor::Direction direction)
  {
    if (direction == UserSessionPacketProcessor::Direction::D_OUTPUT)
    {
      return DIRECTION_OUTPUT_STR;
    }

    if (direction == UserSessionPacketProcessor::Direction::D_INPUT)
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

  PacketProcessingState
  CompositeUserSessionPacketProcessor::process_user_session_packet(
    const Gears::Time& time,
    const UserPtr& user,
    uint32_t src_ip,
    uint32_t dst_ip,
    Direction direction,
    const SessionKey& session_key,
    uint64_t packet_size,
    const void* packet)
  {
    PacketProcessingState processing_state;

    for (auto& child : childs_)
    {
      processing_state += child->process_user_session_packet(
        time,
        user,
        src_ip,
        dst_ip,
        direction,
        session_key,
        packet_size,
        packet);

      if (processing_state.block_packet)
      {
        break;
      }
    }

    return processing_state;
  }
}
