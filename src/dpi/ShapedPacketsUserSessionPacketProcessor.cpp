#include <sstream>

#include "NetworkUtils.hpp"
#include "ShapedPacketsUserSessionPacketProcessor.hpp"

namespace dpi
{
  ShapedPacketsUserSessionPacketProcessor::ShapedPacketsUserSessionPacketProcessor()
  {}

  PacketProcessingState
  ShapedPacketsUserSessionPacketProcessor::process_user_session_packet(
    const Gears::Time& now,
    const UserPtr& user,
    uint32_t src_ip,
    uint32_t dst_ip,
    Direction /*direction*/,
    const SessionKey& session_key,
    uint64_t packet_size,
    const void* packet)
  {
    /*
    PacketProcessingState packet_processing_state = user->process_packet(
      session_rule_config_,
      session_key,
      now,
      packet_size);
    */
    return PacketProcessingState();
  }
}
