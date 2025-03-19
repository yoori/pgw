#pragma once

#include "UserSessionPacketProcessor.hpp"

namespace dpi
{
  class StatPacketProcessor: public UserSessionPacketProcessor
  {
  public:
    virtual bool process_user_session_packet(
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
      const SessionKey& session_key,
      uint64_t packet_size) override;
  };
}
