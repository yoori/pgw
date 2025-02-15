#ifndef GEARS_DELEGATETASKGOAL_HPP_
#define GEARS_DELEGATETASKGOAL_HPP_

#include <type_traits>

#include <gears/TaskRunner.hpp>
#include <gears/Planner.hpp>
#include <gears/BoolFunctors.hpp>

namespace Gears
{
  typedef std::shared_ptr<Gears::TaskGoal>
    TaskGoal_var;

  typedef std::shared_ptr<Gears::GoalTask>
    GoalTask_var;

  template<typename Delegate>
  TaskGoal_var
  make_delegate_goal_task(
    const Delegate& delegate,
    Gears::TaskRunner* task_runner)
    /*throw(Gears::Exception)*/;

  /**
   * create task that start execution loop (after first execution) with predefined period
   * if function will return false execution loop will be interrupted
   * if function return type is void exection loop uninterruptable
   */
  template<typename Delegate>
  GoalTask_var
  make_goal_task(
    const Delegate& delegate,
    Gears::TaskRunner* task_runner,
    Gears::Planner* planner,
    const Gears::Time& update_period)
    /*throw (Gears::Exception)*/;

  template<typename Delegate>
  Gears::Task_var
  make_delegate_task(const Delegate& delegate)
    /*throw(Gears::Exception)*/;

  /**
   * create task that will reexecuted for time returned from delegate
   * execution will be stopped if returned time is ZERO
   */    
  template<typename Delegate>
  GoalTask_var
  make_repeating_task(
    const Delegate& delegate,
    Gears::TaskRunner* task_runner,
    Gears::Planner* planner)
    /*throw (Gears::Exception)*/;
}

namespace Gears
{
  template<typename Delegate>
  class DelegateTask: public Gears::Task
  {
  public:
    DelegateTask(const Delegate& delegate)
      /*throw(Gears::Exception)*/
      : delegate_(delegate)
    {}

    virtual
    ~DelegateTask() noexcept = default;

    virtual void
    execute()
    noexcept
    {
      delegate_();
    }

  private:
    Delegate delegate_;
  };

  template<typename Delegate>
  class DelegateTaskGoal : public Gears::TaskGoal
  {
  public:
    DelegateTaskGoal(
      const Delegate& delegate,
      Gears::TaskRunner_var task_runner)
      /*throw(Gears::Exception)*/
      : TaskGoal(task_runner), delegate_(delegate)
    {}

    virtual
    ~DelegateTaskGoal() noexcept
    {}

    virtual void
    execute()
    noexcept
    {
      delegate_();
    }

  private:
    Delegate delegate_;
  };

  /**
   * tparam Delegate must be noexcept functor
   *   with return type convertable to bool
   */
  template <typename Delegate>
  class DelegateGoalTask : public Gears::GoalTask
  {
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

  public:
    DelegateGoalTask(
      const Delegate& delegate,
      Gears::TaskRunner_var task_runner,
      Gears::Planner_var planner)
      /*throw (Gears::Exception)*/
      : GoalTask(planner, task_runner),
        delegate_(delegate)
    {}

    virtual
    ~DelegateGoalTask() noexcept = default;

    virtual void
    execute() /*throw (Gears::Exception)*/
    {
      const Gears::Time next_execution_time = call_();

      if(next_execution_time != Gears::Time::ZERO)
      {
        try
        {
          schedule(next_execution_time);
        }
        catch (const Gears::Exception& ex)
        {
          Gears::ErrorStream ostr;
          ostr << "schedule failed: " << ex.what();
          throw Exception(ostr);
        }
      }
    }

  private:
    Gears::Time
    call_() noexcept
    {
      return delegate_();
    }

    Delegate delegate_;
  };

  template<typename FunctorType, typename ReturnType>
  struct VoidToPeriodHelper
  {
    VoidToPeriodHelper(
      const FunctorType& fun,
      const Gears::Time& /*period*/)
      : fun_(fun)
    {}

    Gears::Time
    operator()() const
    {
      return fun_();
    }

  private:
    FunctorType fun_;
  };

  template<typename FunctorType>
  struct VoidToPeriodHelper<FunctorType, void>
  {
    VoidToPeriodHelper(
      const FunctorType& fun,
      const Gears::Time& period)
      : fun_(fun),
        PERIOD_(period)
    {}

    Gears::Time
    operator()() const
    {
      return fun_(), Gears::Time::get_time_of_day() + PERIOD_;
    }

  private:
    FunctorType fun_;
    const Gears::Time PERIOD_;
  };

  template<class FunctorType>
  VoidToPeriodHelper<FunctorType, typename std::result_of<FunctorType()>::type>
  void_to_period_wrapper(
    const FunctorType& fun,
    const Gears::Time& period)
  {
    return VoidToPeriodHelper<FunctorType, typename std::result_of<FunctorType()>::type>(
      fun,
      period);
  }

  template<typename Delegate>
  Gears::Task_var
  make_delegate_task(const Delegate& delegate)
    /*throw(Gears::Exception)*/
  {
    return Gears::Task_var(new DelegateTask<Delegate>(delegate));
  }

  template<typename Delegate>
  TaskGoal_var
  make_delegate_goal_task(
    const Delegate& delegate,
    Gears::TaskRunner_var task_runner)
    /*throw(Gears::Exception)*/
  {
    return TaskGoal_var(new DelegateTaskGoal<Delegate>(delegate, task_runner));
  }

  template<typename FunctorType>
  GoalTask_var
  make_functor_periodic_task_goal(
    const FunctorType& delegate,
    Gears::TaskRunner_var task_runner,
    Gears::Planner_var planner)
    /*throw (Gears::Exception)*/
  {
    return new DelegateGoalTask<FunctorType>(
      delegate,
      task_runner,
      planner);
  }

  template<typename Delegate>
  GoalTask_var
  make_repeating_task(
    const Delegate& delegate,
    Gears::TaskRunner_var task_runner,
    Gears::Planner_var planner)
    /*throw (Gears::Exception)*/
  {
    return make_functor_periodic_task_goal(
      delegate,
      task_runner,
      planner);
  }

  template<typename Delegate>
  GoalTask_var
  make_goal_task(
    const Delegate& delegate,
    Gears::TaskRunner_var task_runner,
    Gears::Planner_var planner,
    const Gears::Time& execute_period)
    /*throw (Gears::Exception)*/
  {
    return make_functor_periodic_task_goal(
      void_to_period_wrapper(delegate, execute_period),
      task_runner,
      planner);
  }
}

#endif /* GEARS_DELEGATETASKGOAL_HPP_ */
