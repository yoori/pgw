#include "UserSessionPacketProcessor.hpp"

namespace dpi
{
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
    const SessionKey& session_key,
    uint64_t packet_size)
  {
    PacketProcessingState processing_state;

    for (auto& child : childs_)
    {
      processing_state += child->process_user_session_packet(
        time,
        user,
        src_ip,
        dst_ip,
        session_key,
        packet_size);

      if (processing_state.block_packet)
      {
        break;
      }
    }

    return processing_state;
  }
}
