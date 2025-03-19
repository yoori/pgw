#pragma once

#include "User.hpp"
#include "PacketProcessingState.hpp"

namespace dpi
{
  class UserSessionPacketProcessor
  {
  public:
    virtual PacketProcessingState process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
      const SessionKey& session_key,
      uint64_t packet_size) = 0;
  };

  using UserSessionPacketProcessorPtr = std::shared_ptr<UserSessionPacketProcessor>;

  class CompositeUserSessionPacketProcessor: public UserSessionPacketProcessor
  {
  public:
    CompositeUserSessionPacketProcessor();

    void add_child_object(UserSessionPacketProcessorPtr);

    virtual PacketProcessingState process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
      const SessionKey& session_key,
      uint64_t packet_size) override;

  private:
    std::vector<UserSessionPacketProcessorPtr> childs_;
  };
}
