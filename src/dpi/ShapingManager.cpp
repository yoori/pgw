#include "ShapingManager.hpp"

namespace dpi
{
  namespace
  {
    class CerrCallback: public Gears::ActiveObjectCallback
    {
    public:
      virtual void
      report_error(
        Severity,
        const Gears::SubString& description,
        const char* = 0)
        noexcept
      {
        std::cerr << description.str() << std::endl;
      }

      virtual
      ~CerrCallback() noexcept
      {}
    };
  };

  class ShapingManager::CheckPacketsTask: public Gears::TaskGoal
  {
  public:
    CheckPacketsTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      ShapingManager* shaping_manager)
      throw()
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        shaping_manager_(shaping_manager)
    {}

    virtual void
    execute() throw()
    {
      Gears::Time next_check = shaping_manager_->check_packets_();
      planner_->schedule(shared_from_this(), next_check);
    }

  private:
    Gears::Planner_var planner_;
    ShapingManager* shaping_manager_;
  };

  ShapingManager::PacketHolder::PacketHolder(
    const Gears::Time& timestamp_val,
    UserPtr user_val,
    const FlowTraits& flow_traits_val,
    UserSessionPacketProcessor::Direction direction_val,
    const SessionKey& session_key_val,
    std::vector<unsigned char> packet_val,
    NetInterfacePtr net_interface_val // net interface for send packet
    )
    : timestamp(timestamp_val),
      user(std::move(user_val)),
      flow_traits(flow_traits_val),
      direction(direction_val),
      session_key(session_key_val),
      packet(std::move(packet_val)),
      net_interface(std::move(net_interface_val))
  {}

  ShapingManager::ShapingManager(
    UserSessionPacketProcessorPtr shaped_user_session_packet_processor)
    : drop_timeout_(2),
      shaped_user_session_packet_processor_(std::move(shaped_user_session_packet_processor)),
      planner_(std::make_shared<Gears::Planner>(std::make_shared<CerrCallback>())),
      task_runner_(std::make_shared<Gears::TaskRunner>(std::make_shared<CerrCallback>(), 12))
  {
    add_child_object(planner_);
    add_child_object(task_runner_);

    task_runner_->enqueue_task(
      std::make_shared<CheckPacketsTask>(planner_, task_runner_, this));
  }

  void
  ShapingManager::add_shaped_packet(
    const Gears::Time& now,
    UserPtr user,
    const FlowTraits& flow_traits,
    UserSessionPacketProcessor::Direction direction,
    const SessionKey& session_key,
    unsigned long size,
    const void* packet,
    NetInterfacePtr net_interface)
  {
    std::cout << "add_shaped_packet" << std::endl;

    const Gears::Time time_to_send(now.tv_sec + 1);
    std::vector<unsigned char> packet_copy(
      static_cast<const unsigned char*>(packet),
      static_cast<const unsigned char*>(packet) + size);

    auto packet_holder = std::make_shared<PacketHolder>(
      now,
      user,
      flow_traits,
      direction,
      session_key,
      std::move(packet_copy),
      std::move(net_interface));

    add_shaped_packet_(now, std::move(packet_holder));
  }

  void
  ShapingManager::add_shaped_packet_(
    const Gears::Time& time_to_send,
    PacketHolderPtr packet_holder)
  {
    std::unique_lock<std::mutex> guard(lock_);
    auto& delayed_packets_stats = delayed_packets_stats_[packet_holder->user];
    if (delayed_packets_stats.packets + 1 > max_packets_per_user_)
    {
      return;
    }

    if (delayed_packets_stats.bytes + packet_holder->packet.size() > max_bytes_per_user_)
    {
      return;
    }

    delayed_packets_stats.packets += 1;
    delayed_packets_stats.bytes += packet_holder->packet.size();

    delayed_packets_.emplace(
      time_to_send,
      std::move(packet_holder));
  }

  Gears::Time
  ShapingManager::check_packets_()
  {
    const Gears::Time now = Gears::Time::get_time_of_day();
    Gears::Time processed_time_sec;
    std::vector<std::pair<Gears::Time, PacketHolderPtr>> send_packets;

    {
      std::unique_lock<std::mutex> guard(lock_);
      while (!delayed_packets_.empty() && delayed_packets_.begin()->first <= now)
      {
        auto& delayed_packet = delayed_packets_.begin()->second;

        auto stat_it = delayed_packets_stats_.find(delayed_packet->user);
        if (stat_it != delayed_packets_stats_.end())
        {
          stat_it->second.packets -= 1;
          stat_it->second.bytes -= delayed_packet->packet.size();
        }

        send_packets.emplace_back(
          delayed_packets_.begin()->first,
          std::move(delayed_packet));
        delayed_packets_.erase(delayed_packets_.begin());
      }
    }

    // send delayed packets
    for (auto& [send_timestamp, send_packet] : send_packets)
    {
      if (send_timestamp + drop_timeout_ >= now)
      {
        PacketProcessingState processing_state;
        shaped_user_session_packet_processor_->process_user_session_packet(
          processing_state,
          send_timestamp,
          send_packet->user,
          send_packet->flow_traits,
          send_packet->direction,
          send_packet->session_key,
          send_packet->packet.size(),
          &send_packet->packet[0]);

        if (!processing_state.block_packet)
        {
          if (processing_state.shaped) //< shaped again
          {
            add_shaped_packet_(
              send_timestamp + resend_period_,
              std::move(send_packet));
          }
          else
          {
            send_packet->net_interface->send(
              &send_packet->packet[0],
              send_packet->packet.size());
          }
        }
      }
      else
      {
        // Drop packet
      }
    }

    if (processed_time_sec != Gears::Time::ZERO)
    {
      return Gears::Time(processed_time_sec.tv_sec + 1);
    }

    return Gears::Time::get_time_of_day() + Gears::Time::ONE_SECOND;
  }
}
