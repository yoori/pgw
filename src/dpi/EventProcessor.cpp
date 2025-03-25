#include <sstream>

#include "EventProcessor.hpp"

namespace dpi
{
  EventProcessor::EventProcessor(LoggerPtr event_logger)
    : event_logger_(std::move(event_logger))
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
  }

  bool EventProcessor::process_event(
    UserPtr user,
    std::string_view event_name,
    std::string_view message)
    const
  {
    std::cout << "Process event: " << event_name << std::endl;

    const Gears::Time now = Gears::Time::get_time_of_day();
    const std::string event_name_val(event_name);
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
}
