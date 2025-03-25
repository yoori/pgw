#pragma once

#include <mutex>

#include <gears/CompositeActiveObject.hpp>
#include <gears/Planner.hpp>
#include <gears/TaskRunner.hpp>

#include "User.hpp"
#include "UserSessionPacketProcessor.hpp"
#include "NetInterfaceProcessor.hpp"

namespace dpi
{
  class ShapingManager: public Gears::CompositeActiveObject
  {
  public:
    ShapingManager(
      UserSessionPacketProcessorPtr shaped_user_session_packet_processor);

    void add_shaped_packet(
      const Gears::Time& now,
      UserPtr user,
      const SessionKey& session_key,
      unsigned long size,
      const void* packet,
      NetInterfacePtr net_interface);

  private:
    struct PacketHolder
    {
      PacketHolder(
        const Gears::Time& timestamp,
        UserPtr user,
        std::vector<unsigned char> packet,
        NetInterfacePtr net_interface
        );

      Gears::Time timestamp;
      UserPtr user;
      std::vector<unsigned char> packet;
      NetInterfacePtr net_interface;
    };

    using PacketHolderPtr = std::shared_ptr<PacketHolder>;

    struct DelayedPacketsStats
    {
      unsigned long packets = 0;
      unsigned long bytes = 0;
    };

    class CheckPacketsTask;

  private:
    Gears::Time check_packets_();

  private:
    const UserSessionPacketProcessorPtr shaped_user_session_packet_processor_;
    Gears::Planner_var planner_;
    Gears::TaskRunner_var task_runner_;
    const unsigned long max_packets_per_user_ = 50;
    const unsigned long max_bytes_per_user_ = 10 * 1024;

    std::mutex lock_;
    std::multimap<Gears::Time, PacketHolderPtr> delayed_packets_;
    std::unordered_map<UserPtr, DelayedPacketsStats> delayed_packets_stats_;
  };

  using ShapingManagerPtr = std::shared_ptr<ShapingManager>;
};
