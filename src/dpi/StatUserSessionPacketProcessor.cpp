#include <stdio.h>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iomanip>

#include "NetworkUtils.hpp"
#include "StatUserSessionPacketProcessor.hpp"

namespace dpi
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

  // StatUserSessionPacketProcessor::StatsDumpTask
  class StatUserSessionPacketProcessor::StatsDumpTask: public Gears::TaskGoal
  {
  public:
    StatsDumpTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      StatUserSessionPacketProcessor* stat_user_session_packet_processor)
      throw()
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        stat_user_session_packet_processor_(stat_user_session_packet_processor)
    {}

    virtual void
    execute() throw()
    {
      Gears::Time next_check = stat_user_session_packet_processor_->dump_stats_();
      planner_->schedule(shared_from_this(), next_check);
    }

  private:
    Gears::Planner_var planner_;
    StatUserSessionPacketProcessor* stat_user_session_packet_processor_;
  };

  std::ostream&
  operator<<(std::ostream& out, const StatUserSessionPacketProcessor::StatKey& dump_value)
  {
    out << dump_value.date.get_gm_time().format("%F %T") << "," <<
      dump_value.msisdn << "," <<
      dump_value.traffic_type << "," <<
      dump_value.traffic_category << "," <<
      ipv4_address_to_string(dump_value.src_ip) << "," <<
      ipv4_address_to_string(dump_value.dst_ip) << "," <<
      direction_to_string(dump_value.direction)
      ;
    return out;
  }

  // StatUserSessionPacketProcessor impl
  StatUserSessionPacketProcessor::StatUserSessionPacketProcessor(
    std::string ch_dump_path,
    const Gears::Time& dump_period)
    : ch_dump_path_(ch_dump_path),
      dump_period_(dump_period)
  {
    Gears::ActiveObjectCallback_var callback(new CerrCallback());
    task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 1));
    add_child_object(task_runner_);
    planner_ = Gears::Planner_var(new Gears::Planner(callback));
    add_child_object(planner_);

    task_runner_->enqueue_task(
      std::make_shared<StatsDumpTask>(planner_, task_runner_, this));
  }

  void
  StatUserSessionPacketProcessor::process_user_session_packet(
    PacketProcessingState& packet_processing_state,
    const Gears::Time& time,
    const UserPtr& user,
    const FlowTraits& flow_traits,
    Direction direction,
    const SessionKey& session_key,
    uint64_t packet_size,
    const void* // packet
    )
  {
    //const Gears::Time log_time(time.tv_sec / 60 * 60);
    const Gears::Time log_time(time.tv_sec);
    int64_t bytes =
      !packet_processing_state.block_packet && !packet_processing_state.shaped ?
      packet_size : 0;

    /*
    if (session_key.traffic_type() == "telegram_voip")
    {
      std::cout << "STAT:"
        " traffic_type = " << session_key.traffic_type() <<
        ", category_type = " << session_key.category_type() <<
        ", timestamp = " << time.tv_sec <<
        ", bytes = " << bytes <<
        std::endl;
    }
    */

    detailed_stat_collector_.add_record(
      StatKey(
        log_time,
        user ? user->msisdn() : std::string(),
        session_key.traffic_type(),
        session_key.category_type(),
        flow_traits.src_ip,
        flow_traits.dst_ip,
        direction
        ),
      StatValue(
        (!packet_processing_state.block_packet && !packet_processing_state.shaped ?
          1 : 0),
        bytes,
        (!packet_processing_state.block_packet && packet_processing_state.shaped ?
         1 : 0), //< shaped packets
        (!packet_processing_state.block_packet && packet_processing_state.shaped ?
          packet_size : 0),
        packet_processing_state.block_packet ? 1 : 0, //< dropped packets
        packet_processing_state.block_packet ? packet_size : 0
        ));
  }

  std::pair<std::string, std::string>
  StatUserSessionPacketProcessor::generate_file_name_(const std::string& prefix)
  {
    static const char DATE_FMT[] = "%Y%m%d.%H%M%S.%q";
    std::ostringstream ostr;
    long rand_value = static_cast<long int>(99999999. * (random() / (RAND_MAX + 1.))) + 1;
    ostr << prefix << "." << Gears::Time::get_time_of_day().get_gm_time().format(DATE_FMT) <<
      "." << std::setfill('0') << std::setw(8) << rand_value << ".csv";
    return std::make_pair(std::string("~") + ostr.str(), ostr.str());
  }

  void
  StatUserSessionPacketProcessor::dump()
  {
    {
      // dump detailed
      std::pair<std::string, std::string> fp = generate_file_name_("DetailedTrafficStats");
      if(detailed_stat_collector_.dump(ch_dump_path_ + "/" + fp.first))
      {
        ::rename((ch_dump_path_ + "/" + fp.first).c_str(), (ch_dump_path_ + "/" + fp.second).c_str());
      }
    }
  }

  Gears::Time
  StatUserSessionPacketProcessor::dump_stats_() noexcept
  {
    try
    {
      //std::cerr << "[INFO] DUMP STATS" << std::endl;
      dump();
    }
    catch(const Gears::Exception& ex)
    {
      std::cerr << "[ERROR] dump stats, caught exception: " << ex.what() << std::endl;
    }

    return Gears::Time::get_time_of_day() + dump_period_;
  }
}
