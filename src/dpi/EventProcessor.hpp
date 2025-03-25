#pragma once

#include <shared_mutex>
#include <optional>

#include <gears/Time.hpp>

#include "Logger.hpp"
#include "User.hpp"

namespace dpi
{
  class EventProcessor
  {
  public:
    struct BlockSession
    {
      SessionKey session_key;
      Gears::Time block_for;
    };

    // rule for process event
    struct EventAction
    {
      bool log = true;
      bool block_current_session = false;
      std::optional<BlockSession> block_session;
    };

    EventProcessor(LoggerPtr event_logger);

    // return true if need to send packet
    bool process_event(
      UserPtr user,
      std::string_view event_name,
      std::string_view message) const;

    /*
    void set_event_action(
      std::string_view event_name,
      const EventAction& event_action);
    */

    void set_event_action(
      std::string_view event_name,
      const std::vector<EventAction>& event_actions);

  private:
    using EventActionPtr = std::shared_ptr<const EventAction>;

  private:
    const LoggerPtr event_logger_;

    mutable std::shared_mutex lock_;
    std::unordered_map<std::string, std::vector<EventActionPtr>> event_actions_;
  };

  using EventProcessorPtr = std::shared_ptr<EventProcessor>;
}
