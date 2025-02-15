#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <gears/Errno.hpp>
#include <gears/Listener.hpp>
#include <gears/Singleton.hpp>

namespace
{
  /**
   * Auxiliary class DescriptorsHolder
   * We fill descriptors, class guarantee that all filled
   * descriptors will be close when destroy DescriptorsHolder object.
   * i.e. class is close guard.
   */
  class DescriptorsHolder : private Gears::Uncopyable
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    typedef char Error[sizeof(Exception)];

    /**
     * Allocates memory enough to contain count descriptors.
     * Does not own any descriptors.
     * @param count max count of descriptors, that we can own.
     */
    DescriptorsHolder(size_t count) /*throw (Gears::Exception)*/;

    /**
     * Destructor, closes all owned descriptors.
     */
    ~DescriptorsHolder() noexcept;

    /**
     * Add at end of descriptors array open file descriptor.
     * @param fd must be open file descriptor
     */
    void
    push_back(int fd) /*throw (Exception)*/;

    /**
     * For redefining aims we will close descriptors consequently
     * from end of DescriptorsHolder.
     * @return the last descriptor available.
     */
    int
    pop_back(Error& error) noexcept;

    /**
     * Close all owned descriptors. Call before destruction to get
     * potential closing troubles error info.
     */
    void
    close_all(Error& error) noexcept;

    /**
     * Close all owned descriptors. Call before destruction to get
     * potential closing troubles error info.
     */
    void
    close_all() /*throw (Exception)*/;

    /**
     * Get descriptors array pointer, need to placing at
     * DescriptorListener disposal.
     * @return pointer to descriptors array
     */
    int*
    get() noexcept;

    /**
     * Find fd element in descriptors container.
     * @param fd number for finding in descriptors container.
     * @return pointer to found element, 0 if doesn't contain
     * such element.
     */
    int*
    find(int fd) noexcept;

    /**
     * Get count of open descriptors that owned by descriptor object
     * @return current number of descriptors
     */
    size_t
    count() const noexcept;

  private:
    /**
     * Close descriptors from in (begin, end) range.
     * @param begin range start pointer
     * @param end range end pointer
     */
    void
    close_(const int* begin, const int* end, Error& error)
      /*throw (Gears::Exception)*/;

    std::vector<int> descriptors_;
    size_t used_count_;
    size_t allocated_size_;
  };


  DescriptorsHolder::DescriptorsHolder(size_t count)
    /*throw (Gears::Exception)*/
    : descriptors_(count), used_count_(0), allocated_size_(count)
  {}

  DescriptorsHolder::~DescriptorsHolder() noexcept
  {
    if (used_count_)
    {
      Error error = "";
      close_all(error);
    }
  }

  void
  DescriptorsHolder::push_back(int fd) /*throw (Exception)*/
  {
    static const char* FUN = "DescriptorsHolder::push_back()";

    if (used_count_ == allocated_size_)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": exhausted place to store descriptor";
      throw Exception(ostr.str());
    }
    descriptors_[used_count_++] = fd;
  }

  int
  DescriptorsHolder::pop_back(Error& error) noexcept
  {
    if (used_count_ == 0)
    {
      Gears::StringManip::concat(error, sizeof(error),
        "DescriptorsHolder::pop_back(): has not descriptors on hold");
      return -1;
    }
    return descriptors_[--used_count_];
  }

  int*
  DescriptorsHolder::find(int fd) noexcept
  {
    for (int* p_fd = &descriptors_[0];
      p_fd < &descriptors_[0] + used_count_; ++p_fd)
    {
      if (*p_fd == fd)
      {
        return p_fd;
      }
    }
    return 0;
  }

  void
  DescriptorsHolder::close_all(Error& error) noexcept
  {
    close_(&descriptors_[0], &descriptors_[0] + used_count_, error);
    used_count_ = 0;
  }

  void
  DescriptorsHolder::close_all() /*throw (Exception)*/
  {
    Error error = "";
    close_all(error);
    if (*error)
    {
      throw Exception(error);
    }
  }

  int*
  DescriptorsHolder::get() noexcept
  {
    return &descriptors_[0];
  }

  size_t
  DescriptorsHolder::count() const noexcept
  {
    return used_count_;
  }

  void
  DescriptorsHolder::close_(const int* begin, const int* end, Error& error)
    /*throw (Gears::Exception)*/
  {
    for (const int* fd = begin; fd != end; fd++)
    {
      if (close(*fd) == -1)
      {
        Error string;
        Gears::ErrnoHelper::compose_safe(string, sizeof(string), errno,
          "DescriptorsHolder::close_(): ", "error closing descriptor ", *fd);

        if (*error)
        {
          Gears::StringManip::strlcat(error, "\n", sizeof(error));
        }

        Gears::StringManip::strlcat(error, string, sizeof(error));
      }
    }
  }

  Gears::Mutex execute_and_listen_mutex;

  void
  create_pipes(bool error_pipe, size_t descriptors_amount,
    DescriptorsHolder& read_descriptors, DescriptorsHolder& write_descriptors)
    /*throw (Gears::Exception)*/
  {
    int error_piped[2];
    if (error_pipe)
    {
      if (pipe(error_piped) == -1)
      {
        Gears::throw_errno_exception<
          Gears::DescriptorListener::SysCallFailure>(
            "create_pipes(): ", "pipe fail");
      }
      write_descriptors.push_back(error_piped[1]);
    }

    try
    {
      for (size_t i = 0; i < descriptors_amount; i++)
      {
        int piped[2];
        if (pipe(piped) == -1)
        {
          Gears::throw_errno_exception<
            Gears::DescriptorListener::SysCallFailure>(
              "create_pipes(): ", "pipe fail");
        }
        read_descriptors.push_back(piped[0]);
        write_descriptors.push_back(piped[1]);
      }
    }
    catch (...)
    {
      if (error_pipe)
      {
        read_descriptors.push_back(error_piped[0]);
      }
      throw;
    }

    if (error_pipe)
    {
      read_descriptors.push_back(error_piped[0]);
    }
  }

  void
  child(const char* program_name, char* const argv[],
    size_t descriptors_amount, const int descriptors[],
    size_t redirect_descriptors_amount, const int redirect_descriptors[],
    bool error_pipe, int devnull,
    DescriptorsHolder& read_descriptors, DescriptorsHolder& write_descriptors)
    noexcept
  {
    static const char* FNE = "child(): ";

    // Only reenterable functions are allowed here.
    // STL and other stuff could be non-reenterable (esp. streams).
    // Exceptions are not fork()-compatible too

    DescriptorsHolder::Error error = "";

    setpgrp();

    // Close unused read end
    read_descriptors.close_all(error);

    if (!*error)
    {
      // redirect descriptors to /dev/null
      for (unsigned i = 0; i < redirect_descriptors_amount; i++)
      {
        if (dup2(devnull, redirect_descriptors[i]) < 0)
        {
          Gears::ErrnoHelper::compose_safe(error, sizeof(error), errno,
            FNE, "dup2 failed");
          break;
        }
      }
    }

    if (!*error)
    {
      // redefine supplied descriptors with created pipes
      for (int i = descriptors_amount - 1; i >= 0; i--)
      {
        // To avoid possible clash between parent and child.
        // We must check, that don't redefined yet piping descriptors
        // do not equal child application descriptor, that we will forward
        // to write_descriptor on current iteration.
        // If equal - we dup application descriptor (the same as pipe).
        // Save descriptor from closing by dup2.

        int write_descriptor = write_descriptors.pop_back(error);
        if (*error)
        {
          break;
        }

        if (write_descriptor == descriptors[i])
        {
          continue;
        }
        if (int* clash_with_pipes = write_descriptors.find(descriptors[i]))
        {
          // avoid descriptors[i] closing by dup2 call.
          int new_fd = dup(descriptors[i]);
          if (new_fd == -1)
          {
            Gears::ErrnoHelper::compose_safe(error, sizeof(error), errno,
              FNE, "dup failed");
            break;
          }
          *clash_with_pipes = new_fd;
        }
        // simple forward descriptors in our pipes
        if (dup2(write_descriptor, descriptors[i]) == -1)
        {
          Gears::ErrnoHelper::compose_safe(error, sizeof(error), errno,
            FNE, "dup2 failed");
          break;
        }
        if (close(write_descriptor) == -1)
        {
          Gears::ErrnoHelper::compose_safe(error, sizeof(error), errno,
              FNE, "close failed");
          break;
        }
      }
    }

    if (!*error)
    {
      if (error_pipe)
      {
        if (Gears::set_cloexec(*write_descriptors.get()) < 0)
        {
          Gears::ErrnoHelper::compose_safe(error, sizeof(error), errno,
              FNE, "set_cloexec failed");
        }
      }
    }

    if (!*error)
    {
      // and execute the program
      execvp(program_name, argv);

      Gears::ErrnoHelper::compose_safe(error, sizeof(error), errno,
        FNE, "execvp failed for '", program_name, "'");
    }

    assert(*error);

    if (error_pipe)
    {
      int res = write(*write_descriptors.get(), error, strlen(error));
      (void)res;
    }

    //write_descriptors.close_all(error);

    _exit(255);
  }
}

namespace Gears
{
  //
  // class DescriptorListenerCallback
  //

  void
  DescriptorListenerCallback::on_all_closed() noexcept
  {
    if (listener())
    {
      listener()->terminate();
      listener(0);
    }
  }


  //
  // class DescriptorListener
  //

  const Time DescriptorListener::PERIOD = Time::ONE_SECOND;

  DescriptorListener::DescriptorListener(
    DescriptorListenerCallback_var callback,
    const int* descriptors,
    size_t dscs_amount,
    size_t buffers_size,
    bool full_lines_only)
    /*throw (InvalidArgument, SysCallFailure, EventFailure, Gears::Exception)*/
    : callback_(std::move(callback)),
      DESCRIPTORS_COUNT_(dscs_amount),
      BUFFERS_LENGTH_(buffers_size),
      FULL_LINES_ONLY_(full_lines_only),
      read_contexts_(DESCRIPTORS_COUNT_),
      closed_descriptors_(0)
  {
    static const char* FUN = "DescriptorListener::DescriptorListener()";
    static const char* FNE = "DescriptorListener::DescriptorListener(): ";

    if (!buffers_size)
    {
      ErrorStream ostr;
      ostr << FUN << ": buffer_size is zero";
      throw InvalidArgument(ostr.str());
    }

    // Initialize the event library
    base_ = event_base_new();
    if (base_ == 0)
    {
      Gears::throw_errno_exception<EventFailure>(FNE,
        "event_base_new() failed.");
    }

    try
    {
      // initialize the members of the event structure
      event_set(&termination_, termination_pipe_.read_descriptor(),
        EV_READ, terminate_callback_, this);
      event_base_set(base_, &termination_);
      if (event_add(&termination_, 0) == -1)
      {
        Gears::throw_errno_exception<EventFailure>(FNE,
          "event_add(termination_) failed.");
      }

      // periodic callback
      evtimer_set(&periodic_, periodic_callback_, this);
      event_base_set(base_, &periodic_);
      if (evtimer_add(&periodic_, &PERIOD) == -1)
      {
        Gears::throw_errno_exception<EventFailure>(FNE,
          "event_add(periodic_) failed.");
      }

      // set descriptors for dispatching
      for (size_t i = 0; i < DESCRIPTORS_COUNT_; i++)
      {
        int flags = fcntl(descriptors[i], F_GETFL);
        if (flags == -1 ||
          fcntl(descriptors[i], F_SETFL, flags | O_NONBLOCK) == -1)
        {
          Gears::throw_errno_exception<SysCallFailure>(FNE, "fcntl() failed");
        }
        read_contexts_[i].init(base_, this, BUFFERS_LENGTH_,
          descriptors[i]);
      }
    }
    catch (...)
    {
      event_base_free(base_);
      throw;
    }
  }

  DescriptorListener::~DescriptorListener() noexcept
  {
    event_base_free(base_);
  }

  void
  DescriptorListener::terminate() noexcept
  {
    termination_pipe_.signal();
  }

  void
  DescriptorListener::read_callback_(int fd, short /*type*/, void* arg)
    noexcept
  {
    DescriptorActionContext* context =
      static_cast<DescriptorActionContext*>(arg);
    context->owner->handle_read_(fd, *context);
  }

  void
  DescriptorListener::terminate_callback_(int /*fd*/, short /*type*/,
    void* arg) noexcept
  {
    static const char* FUN = "DescriptorListener::terminate_callback_()";

    DescriptorListener* listener = static_cast<DescriptorListener*>(arg);
    if (event_base_loopexit(listener->base_, 0) == -1)
    {
      ErrorStream ostr;
      ostr << FUN << ": Can't stop event dispatching.";
      listener->callback_->error(ostr.str());
    }
  }

  void
  DescriptorListener::periodic_callback_(int /*fd*/, short /*type*/,
    void* arg) noexcept
  {
    static const char* FUN = "DescriptorListener::periodic_callback_()";

    DescriptorListener* listener = static_cast<DescriptorListener*>(arg);
    listener->callback_->on_periodic();
    if (evtimer_add(&listener->periodic_, &PERIOD) == -1)
    {
      ErrorStream ostr;
      ostr << FUN << ": event_add(periodic_) failed.";
      listener->callback_->error(ostr.str());
    }
  }

  void
  DescriptorListener::handle_read_(int fd, DescriptorActionContext& context)
    noexcept
  {
    for (;;)
    {
      ssize_t res;
      if (!FULL_LINES_ONLY_)
      {
        res = read(fd, &context.buffer[0], BUFFERS_LENGTH_);
      }
      else
      {
        res = read(fd, &context.buffer[0] + context.used_buffer,
          BUFFERS_LENGTH_ - context.used_buffer);
      }

      int error = 0;
      switch (res)
      {
      case -1:
        if (errno == EINTR)
        {
          continue;
        }

        // All data read, and we are finishing callback...
        if (errno == EAGAIN)
        {
          return;
        }
        error = errno;

      case 0:
        event_del(&context.read_event);
        if (context.used_buffer)
        {
          callback_->on_data_ready(fd, &context - &read_contexts_[0],
            &context.buffer[0], context.used_buffer);
        }
        callback_->on_closed(fd, &context - &read_contexts_[0], error);
        if (++closed_descriptors_ == DESCRIPTORS_COUNT_)
        {
          callback_->on_all_closed();
        }
        return;

      default:
        break;
      }

      if (FULL_LINES_ONLY_)
      {
        // 1. buffer can contain rest of previous read (without \n).
        const char* chunk = &context.buffer[0] + context.used_buffer;
        const char* line_start = &context.buffer[0];
        while (const char* line_end =
          static_cast<const char*>(memchr(chunk, '\n', res)))
        {
          // found new line
          callback_->on_data_ready(fd, &context - &read_contexts_[0],
            line_start, line_end - line_start + 1);
          res -= line_end - chunk + 1;
          line_start = chunk = line_end + 1;
        }
        // check overflow
        if (context.used_buffer + res == BUFFERS_LENGTH_)
        {
          callback_->on_data_ready(fd, &context - &read_contexts_[0],
            line_start, BUFFERS_LENGTH_);
          context.used_buffer = 0;
          continue;
        }
        // if had new lines
        if (chunk != &context.buffer[0] + context.used_buffer)
        {
          memmove(&context.buffer[0], chunk, res);
          context.used_buffer = res;
        }
        else
        {
          context.used_buffer += res;
        }
      }
      else
      {
        callback_->on_data_ready(fd, &context - &read_contexts_[0],
          &context.buffer[0], res);
      }
    }
  }

  void
  DescriptorListener::listen() /*throw (Gears::Exception, EventFailure)*/
  {
    // loop and dispatch events
    if (event_base_dispatch(base_) < 0)
    {
      Gears::throw_errno_exception<EventFailure>(
        "DescriptorListener::listen(): ",
        "event_base_dispatch() failure");
    }
  }

  //
  // class DescriptorListener::DescriptorActionContext
  //

  void
  DescriptorListener::DescriptorActionContext::init(
    event_base* base,
    DescriptorListener* host,
    size_t buffer_size,
    int descriptor)
    /*throw (EventFailure, Gears::Exception)*/
  {
    static const char* FNE = "DescriptorListener::DescriptorActionContext::init(): ";

    owner = host;
    buffer.resize(buffer_size);
    used_buffer = 0;

    // initialize the members of the event structure
    event_set(&read_event, descriptor, EV_READ | EV_PERSIST, read_callback_,
      this);
    event_base_set(base, &read_event);
    if (event_add(&read_event, 0) == -1)
    {
      Gears::throw_errno_exception<EventFailure>(FNE, "event_add() failed.");
    }
  }

  //
  // class ActiveDescriptorListenerCallback
  //

  void
  ActiveDescriptorListenerCallback::on_all_closed() noexcept
  {
    if (listener())
    {
      listener()->deactivate_object();
      listener(ActiveDescriptorListener_var());
    }
  }

  //
  // ActiveDescriptorListener::ListenerJob::DLCAdapter class
  //

  ActiveDescriptorListener::ListenerJob::DLCAdapter::DLCAdapter(
    ActiveDescriptorListenerCallback_var active_callback) noexcept
      : active_callback_(std::move(active_callback))
  {}

  ActiveDescriptorListener::ListenerJob::DLCAdapter::~DLCAdapter() noexcept
  {}

  void
  ActiveDescriptorListener::ListenerJob::DLCAdapter::active_listener(
    ActiveDescriptorListener_var active_listener) noexcept
  {
    active_callback_->listener(active_listener);
  }

  void
  ActiveDescriptorListener::ListenerJob::DLCAdapter::on_data_ready(
    int fd, size_t fd_index, const char* buf, size_t size) noexcept
  {
    active_callback_->on_data_ready(fd, fd_index, buf, size);
  }

  void
  ActiveDescriptorListener::ListenerJob::DLCAdapter::on_closed(
    int fd, size_t fd_index, int error) noexcept
  {
    active_callback_->on_closed(fd, fd_index, error);
  }

  void
  ActiveDescriptorListener::ListenerJob::DLCAdapter::on_all_closed()
    noexcept
  {
    active_callback_->on_all_closed();
  }

  void
  ActiveDescriptorListener::ListenerJob::DLCAdapter::report_error(
    ActiveObjectCallback::Severity severity,
    const Gears::SubString& description,
    const char* error_code) noexcept
  {
    active_callback_->report_error(severity, description,
      error_code);
  }


  //
  // class ActiveDescriptorListener::ListenerJob
  //

  ActiveDescriptorListener::ListenerJob::ListenerJob(
    ActiveDescriptorListenerCallback_var callback,
    const int* descriptors,
    size_t number_of_descriptors,
    size_t buffers_size,
    bool full_lines_only)
    /*throw (Gears::Exception)*/
    : SingleJob(callback),
      DescriptorListener(DLCAdapter_var(new DLCAdapter(callback)),
        descriptors, number_of_descriptors, buffers_size, full_lines_only)
  {}

  ActiveDescriptorListener::ListenerJob::~ListenerJob() noexcept
  {}

  void
  ActiveDescriptorListener::ListenerJob::active_listener(
    ActiveDescriptorListener_var active_listener) noexcept
  {
    static_cast<DLCAdapter&>(*DescriptorListener::callback_).active_listener(
      active_listener);
  }

  void
  ActiveDescriptorListener::ListenerJob::terminate() noexcept
  {
    static const char* FUN = "ActiveDescriptorListener::ListenerJob::terminate()";

    try
    {
      DescriptorListener::terminate();
    }
    catch (const Gears::Exception& ex)
    {
      ErrorStream ostr;
      ostr << FUN << ": failed to terminate DescriptorListener: " << ex.what();
      callback()->error(ostr.str());
    }
  }

  void
  ActiveDescriptorListener::ListenerJob::work() noexcept
  {
    try
    {
      listen();
    }
    catch (const Gears::Exception& ex)
    {
      callback()->error(Gears::SubString(ex.what()));
    }
  }

  //
  // class ActiveDescriptorListener
  //

  ActiveDescriptorListener::ActiveDescriptorListener(
    ActiveDescriptorListenerCallback_var callback,
    const int* descriptors,
    size_t number_of_descriptors,
    size_t buffers_size,
    bool full_lines_only)
    /*throw (Gears::Exception)*/
    : ActiveObjectCommonImpl(
        ListenerJob_var(new ListenerJob(callback, descriptors,
          number_of_descriptors, buffers_size, full_lines_only)), 1)
  {
    static_cast<ListenerJob&>(*SINGLE_JOB_).active_listener(shared_from_this());
  }

  ActiveDescriptorListener::~ActiveDescriptorListener() noexcept
  {}

  //
  // ExecuteAndListenCallback class
  //

  void
  ExecuteAndListenCallback::set_pid(pid_t /*pid*/) noexcept
  {}

  //
  // functions
  //

  int
  execute_and_listen(
    ExecuteAndListenCallback_var callback,
    const char* program_name, char* const argv[],
    size_t descriptors_amount, const int descriptors[],
    size_t redirect_descriptors_amount, const int redirect_descriptors[],
    size_t listener_buffers_size, bool listener_full_lines_only,
    bool error_pipe)
    /*throw (Gears::Exception)*/
  {
    static const char* FNE = "execute_and_listen()";

    // create pipes for DescriptorListener, we redefine
    // descriptors later to now creating descriptors

    int devnull = redirect_descriptors_amount ?
      Singleton<DevNull>::instance().fd() : -1;

    size_t full_descriptors_amount = error_pipe ? descriptors_amount + 1 :
      descriptors_amount;
    DescriptorsHolder read_descriptors(full_descriptors_amount);
    DescriptorsHolder write_descriptors(full_descriptors_amount);

    std::unique_ptr<DescriptorListener> dl;
    pid_t cpid;

    {
      // This mutex prevents others processes except the one we are making
      // right now to inherit write ends of pipes.
      // Unfortunately processes created by means other than
      // execute_and_listen will inherit them.

      Gears::Mutex::WriteGuard guard(execute_and_listen_mutex);

      create_pipes(error_pipe, descriptors_amount,
        read_descriptors, write_descriptors);

      // This may raise an exception, doing it before fork
      dl.reset(new DescriptorListener(callback, read_descriptors.get(),
        full_descriptors_amount, listener_buffers_size,
        listener_full_lines_only));

      callback->listener(dl.get());

      cpid = fork();
      if (cpid == -1)
      {
        Gears::throw_errno_exception<DescriptorListener::SysCallFailure>(
          FNE, "fork failed");
      }

      if (cpid == 0)
      {
        // Child

        child(program_name, argv, descriptors_amount, descriptors,
          redirect_descriptors_amount, redirect_descriptors,
          error_pipe, devnull, read_descriptors, write_descriptors);
      }

      // Mutex is released here
    }


    // Parent

    write_descriptors.close_all();

    callback->set_pid(cpid);

    dl->listen();
    read_descriptors.close_all();

    int status;
    if (waitpid(cpid, &status, 0) == -1)
    {
      Gears::throw_errno_exception<DescriptorListener::SysCallFailure>(
        FNE, "waitpid() failed.");
    }

    return status;
  }
}
