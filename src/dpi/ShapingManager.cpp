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
    std::vector<unsigned char> packet_val,
    NetInterfacePtr net_interface_val // net interface for send packet
    )
    : timestamp(timestamp_val),
      user(std::move(user_val)),
      packet(std::move(packet_val)),
      net_interface(std::move(net_interface_val))
  {}

  ShapingManager::ShapingManager(
    UserSessionPacketProcessorPtr shaped_user_session_packet_processor)
    : shaped_user_session_packet_processor_(std::move(shaped_user_session_packet_processor)),
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
    const SessionKey& session_key,
    unsigned long size,
    const void* packet,
    NetInterfacePtr net_interface)
  {
    const Gears::Time time_to_send(now.tv_sec + 1);
    std::vector<unsigned char> packet_copy(
      static_cast<const unsigned char*>(packet),
      static_cast<const unsigned char*>(packet) + size);

    std::unique_lock<std::mutex> guard(lock_);
    auto& delayed_packets_stats = delayed_packets_stats_[user];
    if (delayed_packets_stats.packets + 1 > max_packets_per_user_)
    {
      return;
    }

    if (delayed_packets_stats.bytes + size > max_bytes_per_user_)
    {
      return;
    }

    delayed_packets_.emplace(
      time_to_send,
      std::make_shared<PacketHolder>(
        now,
        user,
        std::move(packet_copy),
        std::move(net_interface)));

    //
    delayed_packets_stats.packets += 1;
    delayed_packets_stats.bytes += size;
  }

  Gears::Time
  ShapingManager::check_packets_()
  {
    const Gears::Time now = Gears::Time::get_time_of_day();
    Gears::Time processed_time_sec;
    std::vector<PacketHolderPtr> send_packets;

    {
      std::unique_lock<std::mutex> guard(lock_);
      while (!delayed_packets_.empty() && delayed_packets_.begin()->first <= now)
      {
        send_packets.emplace_back(std::move(delayed_packets_.begin()->second));
        delayed_packets_.erase(delayed_packets_.begin());
      }
    }

    // send delayed packets
    if (processed_time_sec != Gears::Time::ZERO)
    {
      return Gears::Time(processed_time_sec.tv_sec + 1);
    }

    return Gears::Time::get_time_of_day() + Gears::Time::ONE_SECOND;
  }
}
