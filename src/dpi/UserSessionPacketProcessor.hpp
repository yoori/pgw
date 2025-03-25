#pragma once

#include "User.hpp"
#include "PacketProcessingState.hpp"

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

    virtual PacketProcessingState process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
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

    virtual PacketProcessingState process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
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
