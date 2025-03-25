#pragma once

namespace dpi
{
  struct PacketProcessingState
  {
    PacketProcessingState() {};

    PacketProcessingState(
      bool block_packet_val,
      bool opened_new_session_val,
      bool shape_packet_val = false)
      : block_packet(block_packet_val),
        opened_new_session(opened_new_session_val),
        shaped(shape_packet_val)
    {}

    PacketProcessingState& operator+=(const PacketProcessingState& right);

    bool block_packet = false;
    bool opened_new_session = false;
    bool shaped = false;
  };
}

namespace dpi
{
  inline PacketProcessingState&
  PacketProcessingState::operator+=(const PacketProcessingState& right)
  {
    block_packet = block_packet || right.block_packet;
    opened_new_session = opened_new_session || right.opened_new_session;
    shaped = shaped || right.shaped;
    return *this;
  }
}
