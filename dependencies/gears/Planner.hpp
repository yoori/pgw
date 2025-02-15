#ifndef GEARS_SCHEDULER_HPP_
#define GEARS_SCHEDULER_HPP_

#include <list>

#include "ActiveObject.hpp"

namespace Gears
{
  class Goal
  {
  public:
    /**
     * Callback function to be called from the scheduler
     */
    virtual
    void
    deliver() /*throw (Gears::Exception)*/ = 0;
  };

  typedef std::shared_ptr<Goal> Goal_var;

  class Planner: public ActiveObjectCommonImpl
  {
  public:
    DECLARE_EXCEPTION(Exception, ActiveObject::Exception);

    /**
     * Constructor
     * @param callback Reference countable callback object to be called
     * for errors
     * @param stack_size stack size for working thread
     * @param delivery_time_adjustment Should delivery_time_shift_ be used
     * for messages' time shift
     */
    Planner(
      ActiveObjectCallback_var callback,
      size_t stack_size = 0,
      bool delivery_time_adjustment = false)
      /*throw (InvalidArgument, Gears::Exception)*/;

    /**
     * Destructor
     * Decreases all unmatched messages' reference counters
     */
    virtual
    ~Planner() noexcept;

    /**
     * Adds goal to the queue. Goal's reference counter is incremented.
     * On error it is unchanged (and object will be freed in the caller).
     * @param goal Object to enqueue
     * @param time Timestamp to match
     */
    void
    schedule(Goal_var goal, const Time& time)
      /*throw (InvalidArgument, Exception, Gears::Exception)*/;

    /**
     * Tries to remove goal from the queue.
     * @param goal Object to remove
     * @return number of entries removed
     */
    unsigned
    unschedule(const Goal* goal)
      /*throw (Gears::Exception)*/;

    /**
     * Clearance of messages' queue
     */
    virtual
    void
    clear() /*throw (Gears::Exception)*/;

  private:
    typedef Gears::Mutex SyncPolicy;

    class PlannerJob: public SingleJob
    {
    public:
      PlannerJob(
        ActiveObjectCallback_var callback,
        bool delivery_time_adjustment) /*throw (Gears::Exception)*/;

      virtual
      ~PlannerJob() noexcept;

      virtual
      void
      work() noexcept;

      virtual
      void
      terminate() noexcept;

      void
      schedule(Goal_var goal, const Time& time)
        /*throw (InvalidArgument, Exception, Gears::Exception)*/;

      unsigned
      unschedule(const Goal* goal)
        /*throw (Gears::Exception)*/;

      void
      clear() noexcept;

    protected:
      /**
       * Element of messages' queue. Composition of Message and
       * associated Time.
       */
      class TimedMessage
      {
      public:
        TimedMessage() noexcept;

        TimedMessage(TimedMessage&) = default;

        /**
         * Constructor
         * @param time Associated time
         * @param goal Shared ownership on goal
         */
        TimedMessage(const Time& time, Goal_var goal) noexcept;

        /**
         * Holding time
         * @return Associated time
         */
        const Time&
        time() const noexcept;

        /**
         * Calls deliver() on owned goal
         */
        void
        deliver() /*throw (Gears::Exception)*/;

        /**
         * Checks if it holds the goal
         * @param goal goal to check against
         * @return true if they coincide
         */
        bool
        is_goal(const Goal* goal) const noexcept;

      private:
        Time time_;
        Goal_var goal_;
      };

      typedef std::list<TimedMessage> TimedList;

      mutable Gears::Condition new_event_in_schedule_;
      bool have_new_events_;  // Predicate for condition!

      TimedList messages_;
      bool delivery_time_adjustment_;
      Time delivery_time_shift_;
    };

    typedef std::shared_ptr<PlannerJob> PlannerJob_var;

    PlannerJob& job_;
  };

  typedef std::shared_ptr<Planner> Planner_var;
}

// Inlines

namespace Gears
{
  //
  // Planner::TimedMessage class
  //

  inline
  Planner::PlannerJob::TimedMessage::TimedMessage() noexcept
  {
  }

  inline
  Planner::PlannerJob::TimedMessage::TimedMessage(
    const Time& time, Goal_var goal) noexcept
    : time_(time),
      goal_(std::move(goal))
  {}

  inline
  const Time&
  Planner::PlannerJob::TimedMessage::time() const noexcept
  {
    return time_;
  }

  inline
  void
  Planner::PlannerJob::TimedMessage::deliver() /*throw (Gears::Exception)*/
  {
    goal_->deliver();
  }

  inline
  bool
  Planner::PlannerJob::TimedMessage::is_goal(const Goal* goal) const
    noexcept
  {
    return goal == goal_.get();
  }


  //
  // Planner class
  //

  inline
  void
  Planner::schedule(Goal_var goal, const Time& time)
    /*throw (InvalidArgument, Exception, Gears::Exception)*/
  {
    job_.schedule(std::move(goal), time);
  }

  inline
  unsigned
  Planner::unschedule(const Goal* goal)
    /*throw (Gears::Exception)*/
  {
    return job_.unschedule(goal);
  }

  inline
  void
  Planner::clear() /*throw (Gears::Exception)*/
  {
    job_.clear();
  }
}

#endif
