#pragma once

#include <shared_mutex>
#include <optional>

#include <gears/Time.hpp>
#include <gears/CompositeActiveObject.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/Planner.hpp>

#include "Logger.hpp"
#include "User.hpp"
#include "StatCollector.hpp"

namespace dpi
{
  class EventProcessor: public Gears::CompositeActiveObject
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

    EventProcessor(LoggerPtr event_logger, std::string ch_dump_path);

    // return true if need to send packet
    bool process_event(
      UserPtr user,
      std::string_view event_name,
      std::string_view message);

    /*
    void set_event_action(
      std::string_view event_name,
      const EventAction& event_action);
    */

    void set_event_action(
      std::string_view event_name,
      const std::vector<EventAction>& event_actions);

    void
    dump();

  private:
    class StatsDumpTask;

    struct StatValue
    {
      StatValue();

      StatValue(
        int64_t count_val);

      StatValue&
      operator+=(const StatValue& right) noexcept;

      int64_t count = 0;
    };

    friend std::ostream&
    operator<<(std::ostream& out, const StatValue& dump_value);

    struct StatKey
    {
      StatKey(
        const Gears::Time& date_val,
        std::string msisdn_val,
        std::string event_val
        );

      bool
      operator==(const StatKey& right) const;

      unsigned long
      hash() const;

      const Gears::Time date;
      const std::string msisdn;
      const std::string event;

    protected:
      void calc_hash_();

    protected:
      unsigned long hash_;
    };

    friend std::ostream&
    operator<<(std::ostream& out, const StatKey& dump_value);

    using DetailedStatCollector = StatCollector<StatKey, StatValue>;

    using EventActionPtr = std::shared_ptr<const EventAction>;

  private:
    Gears::Time
    dump_stats_() noexcept;

    static std::pair<std::string, std::string>
    generate_file_name_(const std::string& prefix);

  private:
    const LoggerPtr event_logger_;
    const std::string ch_dump_path_;
    const Gears::Time dump_period_;
    Gears::TaskRunner_var task_runner_;
    Gears::Planner_var planner_;

    DetailedStatCollector detailed_stat_collector_;

    mutable std::shared_mutex lock_;
    std::unordered_map<std::string, std::vector<EventActionPtr>> event_actions_;
  };

  using EventProcessorPtr = std::shared_ptr<EventProcessor>;
}

namespace dpi
{
  // EventProcessor::StatValue
  inline
  EventProcessor::StatValue::StatValue()
  {}

  inline
  EventProcessor::StatValue::StatValue(
    int64_t count_val)
    : count(count_val)
  {}

  inline EventProcessor::StatValue&
  EventProcessor::StatValue::operator+=(
    const EventProcessor::StatValue& right) noexcept
  {
    count += right.count;
    return *this;
  }

  // EventProcessor::StatKey
  inline
  EventProcessor::StatKey::StatKey(
    const Gears::Time& date_val,
    std::string msisdn_val,
    std::string event_val    )
    : date(date_val),
      msisdn(std::move(msisdn_val)),
      event(std::move(event_val)),
      hash_(0)
  {
    calc_hash_();
  }

  inline bool
  EventProcessor::StatKey::operator==(const StatKey& right) const
  {
    return date == right.date &&
      msisdn == right.msisdn &&
      event == right.event;
  }

  inline unsigned long
  EventProcessor::StatKey::hash() const
  {
    return hash_;
  }

  inline void
  EventProcessor::StatKey::calc_hash_()
  {
    Gears::Murmur64Hash hasher(hash_);
    hash_add(hasher, date.tv_sec);
    hash_add(hasher, msisdn);
    hash_add(hasher, event);
  }

  inline std::ostream&
  operator<<(std::ostream& out, const EventProcessor::StatKey& dump_value)
  {
    out << dump_value.date.get_gm_time().format("%F %T") << "," <<
      dump_value.msisdn << "," <<
      dump_value.event
      ;
    return out;
  }

  inline std::ostream&
  operator<<(std::ostream& out, const EventProcessor::StatValue& dump_value)
  {
    out << dump_value.count;
    return out;
  }
}
