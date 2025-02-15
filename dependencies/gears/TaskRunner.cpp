#include <cassert>
#include <algorithm>

#include "TaskRunner.hpp"

namespace Gears
{
  //
  // TaskRunner::TaskRunnerJob class
  //

  TaskRunner::TaskRunnerJob::TaskRunnerJob(
    ActiveObjectCallback_var callback,
    unsigned long number_of_threads,
    unsigned long max_pending_tasks)
    /*throw(Gears::Exception)*/
    : SingleJob(std::move(callback)),
      NUMBER_OF_THREADS_(number_of_threads),
      new_task_(0),
      not_full_(static_cast<int>(std::min<unsigned long>(max_pending_tasks, SEM_VALUE_MAX))),
      LIMITED_(max_pending_tasks)
  {}

  TaskRunner::TaskRunnerJob::~TaskRunnerJob() noexcept
  {}

  void
  TaskRunner::TaskRunnerJob::clear() /*throw(Gears::Exception)*/
  {
    SyncPolicy::WriteGuard guard(mutex());
    if(LIMITED_)
    {
      for(size_t i = tasks_.size(); i; i--)
      {
        not_full_.release();
      }
    }
    tasks_.clear();
  }

  void
  TaskRunner::TaskRunnerJob::enqueue_task(
    Task_var task,
    const Time* /*timeout*/)
    /*throw(InvalidArgument, Overflow, NotActive, Gears::Exception)*/
  {
    static const char* FUN = "TaskRunner::TaskRunnerJob::enqueue_task()";

    if(!task)
    {
      ErrorStream ostr;
      ostr << FUN << ": task is NULL";
      throw InvalidArgument(ostr.str());
    }

    // Producer
    if(LIMITED_)
    {
//    if(!(timeout ? not_full_.timed_acquire(timeout) :
//      not_full_.try_acquire()))
      if(not_full_.try_acquire())
      {
        ErrorStream ostr;
        ostr << FUN << ": TaskRunner overflow";
        throw Overflow(ostr.str());
      }
    }

    {
      SyncPolicy::WriteGuard guard(mutex());
      try
      {
        tasks_.emplace_back(std::move(task));
      }
      catch (...)
      {
        if(LIMITED_)
        {
          not_full_.release();
        }
        throw;
      }
    }
    // Wake any working thread
    new_task_.release();
  }

  void
  TaskRunner::TaskRunnerJob::wait_for_queue_exhausting() /*throw(Gears::Exception)*/
  {
    for(;;)
    {
      {
        SyncPolicy::ReadGuard guard(mutex());
        if(tasks_.empty())
        {
          return;
        }
      }
      Gears::Time wait(0, 300000);
      select(0, 0, 0, 0, &wait);
    }
  }

  void
  TaskRunner::TaskRunnerJob::work() noexcept
  {
    static const char* FUN = "TaskRunner::TaskRunnerJob::work()";

    try
    {
      for(;;)
      {
        Task_var task;
        {
          new_task_.acquire();
          SyncPolicy::WriteGuard guard(mutex());
          if(is_terminating())
          {
            break;
          }
          assert(!tasks_.empty());
          task = tasks_.front();
          tasks_.pop_front();
        }

        // Tell any blocked thread that the queue is ready for a "new item"
        if(LIMITED_)
        {
          not_full_.release();
        }

        try
        {
          task->execute();
        }
        catch (const Gears::Exception& ex)
        {
          callback()->report_error(
            ActiveObjectCallback::ERROR,
            SubString(ex.what()));
        }
      }
    }
    catch (const Gears::Exception& e)
    {
      ErrorStream ostr;
      ostr << FUN << ": Gears::Exception: " << e.what();
      callback()->report_error(
        ActiveObjectCallback::CRITICAL_ERROR,
        ostr.str());
    }
  }

  void
  TaskRunner::TaskRunnerJob::terminate() noexcept
  {
    for(unsigned long i = NUMBER_OF_THREADS_; i; i--)
    {
      new_task_.release();
    }
  }

  //
  // TaskRunner class
  //

  TaskRunner::TaskRunner(
    ActiveObjectCallback_var callback,
    unsigned int threads_number,
    size_t stack_size,
    unsigned long max_pending_tasks)
    /*throw(InvalidArgument, Exception, Gears::Exception)*/
    : ActiveObjectCommonImpl(
        TaskRunnerJob_var(new TaskRunnerJob(
          std::move(callback),
          threads_number,
          max_pending_tasks)),
        threads_number, stack_size),
      job_(static_cast<TaskRunnerJob&>(*SINGLE_JOB_))
  {}

  TaskRunner::~TaskRunner() noexcept
  {}
}
