#include "User.hpp"
#include "PacketProcessingState.hpp"

namespace dpi
{
  PacketProcessingState::PacketProcessingState()
  {}

  PacketProcessingState::PacketProcessingState(
    bool block_packet_val,
    bool opened_new_session_val,
    bool shape_packet_val)
    : block_packet(block_packet_val),
      opened_new_session(opened_new_session_val),
      shaped(shape_packet_val)
  {}

  PacketProcessingState::~PacketProcessingState()
  {}
}
