#include <sstream>
#include <iomanip>

#include "EventProcessor.hpp"

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
  }

  // EventProcessor::StatsDumpTask
  class EventProcessor::StatsDumpTask: public Gears::TaskGoal
  {
  public:
    StatsDumpTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      EventProcessor* event_processor)
      throw()
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        event_processor_(event_processor)
    {}

    virtual void
    execute() throw()
    {
      Gears::Time next_check = event_processor_->dump_stats_();
      planner_->schedule(shared_from_this(), next_check);
    }

  private:
    Gears::Planner_var planner_;
    EventProcessor* event_processor_;
  };

  EventProcessor::EventProcessor(LoggerPtr event_logger, std::string ch_dump_path)
    : event_logger_(std::move(event_logger)),
      ch_dump_path_(std::move(ch_dump_path))
  {
    // fill default rules
    EventAction default_event_action;
    default_event_action.log = true;
    set_event_action("sber-online open", {default_event_action});
    set_event_action("alfabank-online open", {default_event_action});
    set_event_action("gosuslugi open", {default_event_action});
    set_event_action("telegram_voip open", {default_event_action});
    set_event_action("remote-control open", {default_event_action});

    set_event_action("sber-online open on telegram_voip", {default_event_action});
    set_event_action("alfabank-online open on telegram_voip", {default_event_action});
    set_event_action("gosuslugi open on telegram_voip", {default_event_action});

    EventAction block_current_session_event_action;
    block_current_session_event_action.block_current_session = true;
    set_event_action("fishing", {block_current_session_event_action});

    Gears::ActiveObjectCallback_var callback(new CerrCallback());
    task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 1));
    add_child_object(task_runner_);
    planner_ = Gears::Planner_var(new Gears::Planner(callback));
    add_child_object(planner_);

    task_runner_->enqueue_task(
      std::make_shared<StatsDumpTask>(planner_, task_runner_, this));
  }

  bool EventProcessor::process_event(
    UserPtr user,
    std::string_view event_name,
    std::string_view message)
  {
    std::cout << "Process event: " << event_name << std::endl;

    const Gears::Time now = Gears::Time::get_time_of_day();
    const std::string event_name_val(event_name);

    detailed_stat_collector_.add_record(
      StatKey(
        now,
        user ? user->msisdn() : std::string(),
        event_name_val),
      StatValue(1));

    std::vector<EventActionPtr> event_actions;

    {
      std::shared_lock<std::shared_mutex> guard(lock_);
      auto it = event_actions_.find(event_name_val);
      if (it != event_actions_.end())
      {
        event_actions = it->second;
      }
    }

    bool send_packet = true;

    if (!event_actions.empty())
    {
      bool logged = false;

      for (const auto& event_action : event_actions)
      {
        if (event_action->log && !logged)
        {
          std::ostringstream ostr;
          ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] [sber-telecom] EVENT '" <<
            event_name << "': " <<
            user->to_string() << (!message.empty() ? message : std::string_view()) <<
            std::endl;
          event_logger_->log(ostr.str());
          logged = true;
        }

        if (event_action->block_current_session)
        {
          send_packet = false;
        }

        if (user && event_action->block_session.has_value())
        {
          user->session_block(
            event_action->block_session->session_key,
            now + event_action->block_session->block_for);
        }
      }
    }

    return send_packet;
  }

  void EventProcessor::set_event_action(
    std::string_view event_name,
    const std::vector<EventAction>& event_actions)
  {
    const std::string event_name_val(event_name);

    std::vector<std::shared_ptr<const EventAction>> new_event_actions;
    for (const auto& a : event_actions)
    {
      new_event_actions.emplace_back(std::make_shared<const EventAction>(a));
    }
    
    std::unique_lock<std::shared_mutex> guard(lock_);
    event_actions_[event_name_val] = new_event_actions;
  }

  void
  EventProcessor::dump()
  {
    {
      // dump detailed
      std::pair<std::string, std::string> fp = generate_file_name_("DetailedEventStats");
      if(detailed_stat_collector_.dump(ch_dump_path_ + "/" + fp.first))
      {
        ::rename((ch_dump_path_ + "/" + fp.first).c_str(), (ch_dump_path_ + "/" + fp.second).c_str());
      }
    }
  }

  Gears::Time
  EventProcessor::dump_stats_() noexcept
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

  std::pair<std::string, std::string>
  EventProcessor::generate_file_name_(const std::string& prefix)
  {
    static const char DATE_FMT[] = "%Y%m%d.%H%M%S.%q";
    std::ostringstream ostr;
    long rand_value = static_cast<long int>(99999999. * (random() / (RAND_MAX + 1.))) + 1;
    ostr << prefix << "." << Gears::Time::get_time_of_day().get_gm_time().format(DATE_FMT) <<
      "." << std::setfill('0') << std::setw(8) << rand_value << ".csv";
    return std::make_pair(std::string("~") + ostr.str(), ostr.str());
  }
}
