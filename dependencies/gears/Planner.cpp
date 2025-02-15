#include "Planner.hpp"
//#include <Gears/Function.hpp>

namespace Gears
{
  //
  // Planner::PlannerJob class
  //

  Planner::PlannerJob::PlannerJob(
    ActiveObjectCallback_var callback,
    bool delivery_time_adjustment)
    /*throw (Gears::Exception)*/
    : SingleJob(std::move(callback)),
      have_new_events_(false),
      delivery_time_adjustment_(delivery_time_adjustment)
  {}

  Planner::PlannerJob::~PlannerJob() noexcept
  {}

  void
  Planner::PlannerJob::terminate() noexcept
  {
    have_new_events_ = true;
    new_event_in_schedule_.signal(); // wake the working thread
  }

  void
  Planner::PlannerJob::schedule(Goal_var goal, const Time& time)
    /*throw (InvalidArgument, Exception, Gears::Exception)*/
  {
    static const char* FUN = "Planner::PlannerJob::schedule()";

    if (!goal)
    {
      ErrorStream ostr;
      ostr << FUN << ": goal is null";
      throw InvalidArgument(ostr.str());
    }

    Time tm(time > Time::ZERO ? time : Time::ZERO);

    bool signal;
    {
      /** sch 1: add message into list */
      Condition::Guard guard(new_event_in_schedule_);

      TimedList::iterator itor(messages_.end());

      while (itor != messages_.begin())
      {
        --itor;
        if (itor->time() < tm)
        {
          ++itor;
          break;
        }
      }

      signal = (itor == messages_.begin());

      TimedMessage m(tm, goal);
      messages_.emplace(itor, m);
      if (signal)
      {
        have_new_events_ = true;
      }
    }
    if (signal)
    {
      /** sch 2: new events into schedule signal */
      new_event_in_schedule_.signal();
    }
  }

  unsigned
  Planner::PlannerJob::unschedule(const Goal* goal)
    /*throw (Gears::Exception)*/
  {
    unsigned removed = 0;

    {
      Condition::Guard guard(new_event_in_schedule_);

      for (TimedList::iterator itor(messages_.begin());
        itor != messages_.end();)
      {
        if (itor->is_goal(goal))
        {
          itor = messages_.erase(itor);
          removed++;
        }
        else
        {
          ++itor;
        }
      }
    }

    return removed;
  }

  void
  Planner::PlannerJob::work() noexcept
  {
    static const char* FUN = "Planner::PlannerJob::work()";

    try
    {
      TimedList pending;
      Time abs_time;
      Time cur_time;

      for (;;)
      {
        Time* pabs_time = 0;

        {
          /** svc 1: make list of pending tasks */
          Condition::Guard guard(new_event_in_schedule_);

          if (is_terminating())
          {
            break;
          }
          cur_time = Time::get_time_of_day();

          while (!messages_.empty())  // pump messages to pending.
          {
            abs_time = messages_.front().time();

            if (delivery_time_adjustment_)
            {
              abs_time = abs_time > delivery_time_shift_ ?
                abs_time - delivery_time_shift_ :
                Time::ZERO;
            }

            // pump all overdue event to pending list.
            //  They will call immediately
            if (abs_time <= cur_time)
            {
              pending.splice(pending.end(), std::move(messages_),
                messages_.begin());
            }
            else
            {
              pabs_time = &abs_time;  // first event in the future
              break;
            }
          }
        } // end data lock

        if (pending.empty())
        {
          /** svc 2: wait semaphore signal */
          bool new_event_in_schedule = true;

          {
            Condition::Guard cond_guard(new_event_in_schedule_);

            while (!have_new_events_)
            {
              try
              {
                new_event_in_schedule = cond_guard.timed_wait(pabs_time);
              }
              catch (const Gears::Exception& e)
              {
                callback()->critical(Gears::SubString(e.what()));
                new_event_in_schedule = false;
              }
              if (!have_new_events_)
              {
                new_event_in_schedule = false;
                break;
              }
            } // while
            if (is_terminating())
            {
              break;
            }
            if (new_event_in_schedule)
            {
              have_new_events_ = false;
            }
          } // Unlock ConditionalGuard condition

          if (new_event_in_schedule)
          {
            if (delivery_time_adjustment_ && pabs_time)
            {
              Time wake_tm(Time::get_time_of_day());
              if (wake_tm > *pabs_time) // if OVERDUE event
              {
                Time shift = wake_tm - *pabs_time; // OVERDUE event
                delivery_time_shift_ = shift / 2;
              }
            }
            continue;
          }
        } // if (pending.empty())

        /** svc 3: deliver pending tasks */
        while (!pending.empty())
        {
          try
          {
            pending.front().deliver();
          }
          catch (const Gears::Exception& ex)
          {
            callback()->error(Gears::SubString(ex.what()));
          }

          pending.pop_front();
        }
      }
    }
    catch (const Gears::Exception& e)
    {
      ErrorStream ostr;
      ostr << FUN << ": Gears::Exception caught: " << e.what();
      callback()->critical(ostr.str());
    }
  }

  void
  Planner::PlannerJob::clear() noexcept
  {
    Condition::Guard guard(new_event_in_schedule_);
    messages_.clear();
  }

  //
  // Planner class
  //

  Planner::Planner(
    ActiveObjectCallback_var callback,
    size_t stack_size,
    bool delivery_time_adjustment) /*throw (InvalidArgument, Gears::Exception)*/
    : ActiveObjectCommonImpl(
        PlannerJob_var(
          new PlannerJob(std::move(callback), delivery_time_adjustment)),
        1, stack_size),
      job_(static_cast<PlannerJob&>(*SINGLE_JOB_))
  {}

  Planner::~Planner() noexcept
  {}
}
