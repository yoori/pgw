#ifndef GEARS_THREADING_TASKRUNNER_HPP
#define GEARS_THREADING_TASKRUNNER_HPP

#include <deque>
#include <memory>

#include <gears/Exception.hpp>
#include <gears/Lock.hpp>

#include "Semaphore.hpp"
#include "ActiveObject.hpp"
#include "Planner.hpp"

namespace Gears
{
  /**
   * General Task to be processed by TaskRunner.
   */
  class Task
  {
  public:
    virtual
    ~Task() noexcept;

    /**
     * Method is called by TaskRunner when the object's order arrives.
     */
    virtual void
    execute() /*throw(Gears::Exception)*/ = 0;
  };

  typedef std::shared_ptr<Task> Task_var;

  /**
   * Performs tasks in several threads parallelly.
   */
  class TaskRunner : public ActiveObjectCommonImpl
  {
  public:
    DECLARE_EXCEPTION(Exception, ActiveObject::Exception);
    DECLARE_EXCEPTION(Overflow, Exception);
    DECLARE_EXCEPTION(NotActive, Exception);

    /**
     * Constructor
     * @param callback not null callback is called on errors
     * @param threads_number number of working threads
     * @param stack_size their stack sizes
     * @param max_pending_tasks maximum task queue length
     */
    TaskRunner(
      ActiveObjectCallback_var callback,
      unsigned int threads_number,
      size_t stack_size = 0,
      unsigned long max_pending_tasks = 0)
      /*throw(InvalidArgument, Exception, Gears::Exception)*/;

    virtual
    ~TaskRunner() noexcept;

    /**
     * Enqueues a task
     * @param task task to enqueue. Number of references is not increased
     * @param timeout maximal absolute wait time before fail on mutex lock
     * until the task is put in the queue. NULL timeout means no wait.
     * If you put limitations on the size of the queue, and it's full,
     * method waits for the release up to timeout
     */
    void
    enqueue_task(Task_var task, const Time* timeout = 0)
      /*throw(InvalidArgument, Overflow, NotActive, Gears::Exception)*/;

    /**
     * Returns number of tasks recently being enqueued
     * This number does not have much meaning in MT environment
     * @return number of tasks enqueued
     */
    unsigned long
    task_count() noexcept;

    /**
     * Waits for the moment task queue is empty and returns control.
     * In MT environment tasks can be added at the very same moment of
     * return of control.
     */
    void
    wait_for_queue_exhausting() /*throw(Gears::Exception)*/;

    /**
     * Clear task queue
     */
    virtual void
    clear() /*throw(Gears::Exception)*/;

  private:
    class TaskRunnerJob: public SingleJob
    {
    public:
      TaskRunnerJob(
        ActiveObjectCallback_var callback,
        unsigned long number_of_threads,
        unsigned long max_pending_tasks)
        /*throw(Gears::Exception)*/;

      virtual
      ~TaskRunnerJob() noexcept;

      virtual void
      work() noexcept;

      virtual void
      terminate() noexcept;

      void
      enqueue_task(Task_var task, const Time* timeout)
        /*throw(InvalidArgument, Overflow, NotActive, Gears::Exception)*/;

      unsigned long
      task_count() noexcept;

      void
      wait_for_queue_exhausting() /*throw(Gears::Exception)*/;

      void
      clear() /*throw(Gears::Exception)*/;

    private:
      typedef Gears::Mutex SyncPolicy;
      typedef std::deque<Task_var> Tasks;

    private:
      const unsigned long NUMBER_OF_THREADS_;
      Tasks tasks_;
      Semaphore new_task_;
      Semaphore not_full_;
      const bool LIMITED_;
    };

    typedef std::shared_ptr<TaskRunnerJob>
      TaskRunnerJob_var;

    TaskRunnerJob& job_;
  };

  typedef std::shared_ptr<TaskRunner>
    TaskRunner_var;

  /**
   * Task with specified RC implementation
   */
  class TaskImpl: public virtual Task
  {
    /**
     * Destructor
     */
    virtual
    ~TaskImpl() noexcept = default;
  };

  /**
   * Should be put into the Planner.
   * When time arrives, it puts itself into TaskRunner.
   */
  class TaskGoal:
    public Goal,
    public Task,
    public std::enable_shared_from_this<TaskGoal>
  {
  public:
    /**
     * Constructor
     * @param task_runner TaskRunner to put the object into.
     */
    TaskGoal(TaskRunner_var task_runner) /*throw(Gears::Exception)*/;

    /**
     * Destructor
     */
    virtual
    ~TaskGoal() noexcept;

    /**
     * Implementation of Goal::deliver.
     * Puts the object into the TaskRunner.
     */
    virtual void
    deliver() /*throw(Gears::Exception)*/;

  private:
    TaskRunner_var task_runner_;
  };

  /**
   * Reusable version of TaskGoal
   */
  class GoalTask:
    public Goal,
    public Task,
    public std::enable_shared_from_this<TaskGoal>
  {
  public:
    /**
     * Constructor
     * After the object construction call deliver() to put the object into the
     * TaskRunner or schedule_() to put it into the Planner.
     * @param planner Planner to put the object into.
     * @param task_runner TaskRunner to put the object into.
     * or in Planner otherwisee
     */
    GoalTask(Planner_var planner, TaskRunner_var task_runner) /*throw(Gears::Exception)*/;

    /**
     * Implementation of Goal::deliver.
     * Puts the object into the TaskRunner.
     */
    virtual void
    deliver() /*throw(Gears::Exception)*/;

    /**
     * Put the object into the Planner. Call this in execute().
     * @param when time of putting the object into the TaskRunner
     */
    void
    schedule(const Time& time) /*throw(Gears::Exception)*/;

  protected:
    /**
     * Destructor
     */
    virtual
    ~GoalTask() noexcept;

  private:
    Planner_var planner_;
    TaskRunner_var task_runner_;
  };
}

//
// Inlines
//

namespace Gears
{
  //
  // Task class
  //

  inline
  Task::~Task() noexcept
  {}

  //
  // TaskGoal class
  //

  inline
  TaskGoal::TaskGoal(TaskRunner_var task_runner)
    /*throw(Gears::Exception)*/
    : task_runner_(std::move(task_runner))
  {}

  inline
  TaskGoal::~TaskGoal() noexcept
  {}

  inline void
  TaskGoal::deliver() /*throw(Gears::Exception)*/
  {
    task_runner_->enqueue_task(shared_from_this());
  }

  //
  // GoalTask class
  //

  inline
  GoalTask::GoalTask(Planner_var planner, TaskRunner_var task_runner)
    /*throw(Gears::Exception)*/
    : planner_(std::move(planner)),
      task_runner_(std::move(task_runner))
  {}

  inline
  GoalTask::~GoalTask() noexcept
  {}

  inline
  void
  GoalTask::deliver() /*throw(Gears::Exception)*/
  {
    task_runner_->enqueue_task(shared_from_this());
  }

  inline
  void
  GoalTask::schedule(const Time& when) /*throw(Gears::Exception)*/
  {
    planner_->schedule(shared_from_this(), when);
  }

  //
  // TaskRunner::TaskRunnerJob class
  //

  inline
  unsigned long
  TaskRunner::TaskRunnerJob::task_count() noexcept
  {
    SyncPolicy::ReadGuard guard(mutex());
    return tasks_.size();
  }

  //
  // TaskRunner class
  //

  inline
  void
  TaskRunner::enqueue_task(Task_var task, const Time* timeout)
    /*throw(InvalidArgument, Overflow, NotActive, Gears::Exception)*/
  {
    job_.enqueue_task(task, timeout);
  }

  inline
  unsigned long
  TaskRunner::task_count() noexcept
  {
    return job_.task_count();
  }

  inline
  void
  TaskRunner::wait_for_queue_exhausting() /*throw(Gears::Exception)*/
  {
    job_.wait_for_queue_exhausting();
  }

  inline
  void
  TaskRunner::clear() /*throw(Gears::Exception)*/
  {
    job_.clear();
  }
}

#endif
