#pragma once

#include "SessionKey.hpp"

namespace dpi
{
  class User;
  class UserSession;

  struct PacketProcessingState
  {
    PacketProcessingState();

    PacketProcessingState(
      bool block_packet_val,
      bool opened_new_session_val,
      bool shape_packet_val = false);

    ~PacketProcessingState();

    PacketProcessingState& operator+=(const PacketProcessingState& right);

    std::shared_ptr<User> user;
    std::shared_ptr<UserSession> user_session;
    SessionKey session_key;
    bool block_packet = false;
    bool opened_new_session = false;
    bool shaped = false;
    bool revalidate_gx = false;
    bool revalidate_gy = false;
    bool limit_reached = false; //< set if blocked by limit
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
    revalidate_gx = revalidate_gx || right.revalidate_gx;
    revalidate_gy = revalidate_gy || right.revalidate_gy;
    limit_reached = limit_reached || right.limit_reached;
    return *this;
  }
}
