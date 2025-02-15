#ifndef GENERICS_THREAD_RUNNER_HPP
#define GENERICS_THREAD_RUNNER_HPP

#include <signal.h>
#include <pthread.h>

#include <memory>
#include <algorithm>
#include <vector>

#include "Semaphore.hpp"

namespace Gears
{
  class ThreadRunner;

  /**
   * A job performed by ThreadRunner in the threads.
   */
  class ThreadJob
  {
  public:
    /**
     * Work process for the job.
     */
    virtual
    void
    work() noexcept = 0;

  protected:
    /**
     * Destructor.
     */
    virtual
    ~ThreadJob() noexcept = default;
  };

  typedef std::shared_ptr<ThreadJob> ThreadJob_var;

  /**
   * Callback for each new thread tuning
   */
  class ThreadCallback
  {
  public:
    /**
     * Called in the newly created thread.
     */
    virtual
    void
    on_start() noexcept;

    /**
     * Called in the thread going to terminate.
     */
    virtual
    void
    on_stop() noexcept;

  protected:
    virtual
    ~ThreadCallback() noexcept = default;
  };

  typedef std::shared_ptr<ThreadCallback> ThreadCallback_var;

  /**
   * Creates several threads and executes specified job(s) in them.
   */
  class ThreadRunner
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(AlreadyStarted, Exception);
    DECLARE_EXCEPTION(PosixException, Exception);

    /**
     * Options for threads.
     */
    struct Options
    {
      /**
       * Constructor
       * @param stack_size stack size for the thread.
       * @param thread_callback thread tuner callback
       */
      explicit
      Options(
        size_t stack_size = 0,
        const ThreadCallback_var& thread_callback = ThreadCallback_var())
        noexcept;

      // Default stack size for threads
      static const size_t DEFAULT_STACK_SIZE = 1024 * 1024;

      size_t stack_size;
      ThreadCallback_var thread_callback;
    };

    /**
     * Constructor
     * @param job to be executed in all threads.
     * @param number_of_jobs number of jobs to run concurrently.
     * @param options threads options
     */
    ThreadRunner(
      const ThreadJob_var& job,
      unsigned number_of_jobs,
      const Options& options = Options())
      /*throw (Gears::Exception, PosixException)*/;

    /**
     * Constructor
     * @param functor functor producing jobs
     * @param number_of_jobs number of jobs to produce and run concurrently
     * @param options threads options
     */
    template <typename Functor>
    ThreadRunner(
      unsigned number_of_jobs,
      Functor functor,
      const Options& options = Options())
      /*throw (Gears::Exception, PosixException)*/;

    /**
     * Constructor
     * @param begin beginning of the container with jobs
     * @param end end of the container with jobs
     * @param options threads options
     */
    template <typename ForwardIterator>
    ThreadRunner(
      ForwardIterator begin,
      ForwardIterator end,
      const Options& options = Options())
      /*throw (Gears::Exception, PosixException)*/;

    /**
     * Destructor
     * Waits for threads' completion if they are not terminated yet.
     */
    ~ThreadRunner() noexcept;

    /**
     * Number of jobs to execute
     * @return number of jobs
     */
    unsigned
    number_of_jobs() const noexcept;

    /**
     * Return number of jobs running. Thread unsafe.
     * @return jobs running number
     */
    unsigned
    running() const noexcept;

    /**
     * Creates threads and runs the jobs. If creation of a thread fails,
     * no jobs will run. Thread unsafe.
     * @param to_start number of thread to start (0 - all of them)
     */
    void
    start(unsigned to_start = 0)
      /*throw (AlreadyStarted, PosixException, Gears::Exception)*/;

    /**
     * Creates an additional thread if any is left. Thread unsafe.
     */
    void
    start_one() /*throw (AlreadyStarted, PosixException)*/;

    /**
     * Waits for termination of previously started threads.
     * Thread unsafe.
     */
    void
    wait_for_completion() /*throw (PosixException)*/;

  private:
    static
    void*
    thread_func_(void* arg) noexcept;

    void
    thread_func_(ThreadJob& job) noexcept;

    void
    start_one_thread_() /*throw (PosixException)*/;

    class PThreadAttr
    {
    public:
      explicit
      PThreadAttr(size_t stack_size) /*throw (PosixException)*/;

      ~PThreadAttr() noexcept;

      operator pthread_attr_t*() noexcept;

    private:
      pthread_attr_t attr_;
    };

    struct JobInfo
    {
      JobInfo()
      {}

      JobInfo(ThreadRunner* runner_val, ThreadJob_var job_val)
        : runner(runner_val),
          job(job_val)
      {
        assert(job);
      }
      
      ThreadRunner* runner;
      ThreadJob_var job;
      pthread_t thread_id;
    };

    PThreadAttr attr_;
    ThreadCallback_var thread_callback_;

    // required for implement grouped start logic (see start method description)
    Gears::Semaphore start_semaphore_;
    volatile sig_atomic_t number_running_;

    unsigned number_of_jobs_;
    std::vector<std::unique_ptr<JobInfo> > jobs_;
  };
}

namespace Gears
{
  //
  // ThreadRunner class
  //

  inline
  unsigned
  ThreadRunner::number_of_jobs() const noexcept
  {
    return number_of_jobs_;
  }

  inline
  unsigned
  ThreadRunner::running() const noexcept
  {
    return number_running_;
  }

  template <typename Functor>
  ThreadRunner::ThreadRunner(
    unsigned number_of_jobs,
    Functor functor,
    const Options& options)
    /*throw (Gears::Exception, PosixException)*/
    : attr_(options.stack_size),
      thread_callback_(options.thread_callback),
      start_semaphore_(0),
      number_running_(0),
      number_of_jobs_(number_of_jobs)
  {
    jobs_.reserve(number_of_jobs_);

    for (unsigned i = 0; i < number_of_jobs_; i++)
    {
      jobs_.emplace_back(new JobInfo(this, functor()));
    }
  }

  template <typename ForwardIterator>
  ThreadRunner::ThreadRunner(
    ForwardIterator begin,
    ForwardIterator end,
    const Options& options)
    /*throw (Gears::Exception, PosixException)*/
    : attr_(options.stack_size),
      thread_callback_(options.thread_callback),
      start_semaphore_(0),
      number_running_(0),
      number_of_jobs_(std::distance(begin, end))
  {
    jobs_.reserve(number_of_jobs_);

    for (unsigned i = 0; i < number_of_jobs_; i++)
    {
      jobs_.emplace_back(new JobInfo(this, *begin++));
    }
  }
}

#endif
