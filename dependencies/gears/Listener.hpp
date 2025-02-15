#ifndef GEARS_LISTENER_HPP_
#define GEARS_LISTENER_HPP_

#include <event.h>
#include <memory>

#include <gears/ActiveObject.hpp>
//#include <Gears/ArrayAutoPtr.hpp>
#include <gears/Descriptors.hpp>
#include <gears/Time.hpp>

namespace Gears
{
  class DescriptorListener;
  class ActiveDescriptorListener;

  typedef std::shared_ptr<ActiveDescriptorListener>
    ActiveDescriptorListener_var;

  /**
   * Callback for generalized DescriptorListener
   */
  template <typename Listener, typename ListenerHolder>
  class DescriptorListenerCallbackTempl :
    public virtual ActiveObjectCallback
  {
  public:
    DescriptorListenerCallbackTempl() /*throw (Gears::Exception)*/;

    /**
     * Stored listener in the internal variable.
     * Useful for default on_all_closed() implementation.
     * @param new_listener pointer to object that calls the callback.
     */
    void
    listener(ListenerHolder new_listener) noexcept;

    /**
     * Stored listener
     * @return stored listener pointer
     */
    Listener*
    listener() noexcept;

    /**
     * Event data available, data string is not zero terminated!
     * @param fd file descriptor which was the cause of the event.
     * @param fd_index index fd in original array of descriptors, used for
     * listener construction.
     * @param str string with data, not zero terminated.
     * @param size length for data string.
     */
    virtual
    void
    on_data_ready(int fd, size_t fd_index, const char* str, size_t size)
      noexcept = 0;

    /**
     * Called when a read on a descriptor does not provide data.
     * By default does nothing.
     * @param fd descriptor that has been closed or read fails.
     * @param fd_index index fd in original array of descriptors, used for
     * listener construction.
     * @param error 0 if someone closed descriptor, non zero
     * errno value if read() failed.
     */
    virtual
    void
    on_closed(int fd, size_t fd_index, int error) noexcept;

    /**
     * Called when all descriptors used for Listener creation are closed.
     * Useful reaction is to terminate the listener and destroy it
     * as useless.
     */
    virtual
    void
    on_all_closed() noexcept = 0;

    /**
     * Periodically called.
     * By default does nothing.
     */
    virtual
    void
    on_periodic() noexcept;

  protected:
    /**
     * Destructor
     */
    virtual
    ~DescriptorListenerCallbackTempl() noexcept;

  private:
    ListenerHolder listener_;
  };

  /**
   * Callback for the-same-thread DescriptorListener.
   * Called when data packs available for using.
   * Closes descriptor listener when all descriptors are gone.
   */
  class DescriptorListenerCallback :
    public DescriptorListenerCallbackTempl<DescriptorListener,
      DescriptorListener*>
  {
  public:
    /**
     * Calls terminate() for the listener.
     */
    virtual
    void
    on_all_closed() noexcept;

  protected:
    /**
     * Destructor
     */
    virtual
    ~DescriptorListenerCallback() noexcept;
  };

  typedef std::shared_ptr<DescriptorListenerCallback>
    DescriptorListenerCallback_var;

  /**
   * Hang on descriptors and call callbacks when data available.
   * Don't use heap for message buffering.
   * The same thread version.
   */
  class DescriptorListener
  {
  public:
    /**
     * Base exception for all class exceptions.
     */
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    /**
     * Raise if incorrect argument specified.
     */
    DECLARE_EXCEPTION(InvalidArgument, Exception);
    /**
     * Raise if system API errors occurred.
     */
    DECLARE_EXCEPTION(SysCallFailure, Exception);
    /**
     * Raise if libevent errors occurred.
     */
    DECLARE_EXCEPTION(EventFailure, Exception);

    /**
     * Construct finish events.
     * @param callback reporting errors and actions callback.
     * @param descriptors file descriptors, we will read data from it and
     * call callbacks when data has been got.
     * @param dscs_amount number of file descriptors.
     * @param buffers_size buffer size for each descriptor, used to read data.
     * Cannot be 0.
     * @param full_lines_only switch on buffering mode, false mean
     * immediately call data_ready() callback.
     */
    DescriptorListener(
      DescriptorListenerCallback_var callback,
      const int* descriptors, size_t dscs_amount,
      size_t buffers_size = 4096, bool full_lines_only = false)
      /*throw (InvalidArgument, SysCallFailure, EventFailure, Gears::Exception)*/;

    /**
     * Destructor
     */
    ~DescriptorListener() noexcept;

    /**
     * Demultiplex events and call callbacks.
     */
    void
    listen() /*throw (Gears::Exception, EventFailure)*/;

    /**
     * Put stop message in special pipe, when DescriptorListener read it
     * listen call exit.
     */
    void
    terminate() noexcept;

  protected:
    DescriptorListenerCallback_var callback_;

  private:
    /**
     * Context object for each descriptor, contain
     * buffers, data, etc.
     */
    struct DescriptorActionContext
    {
      /**
       * Need for arrays of DescriptorActionContext
       * initialization.
       * @param base general event_base used for event demultiplexing.
       * @param host pointer to object that holds descriptors contexts.
       * @param buffer_size size of static memory used for descriptor read.
       * @param descriptor, open for reading, nonblocking descriptor.
       */
      void
      init(event_base* base, DescriptorListener* host, size_t buffer_size,
        int descriptor) /*throw (EventFailure, Gears::Exception)*/;

      DescriptorListener* owner;
      std::vector<char> buffer;
      size_t used_buffer;
      event read_event;
    };

    /**
     * Called when data for reading is available.
     * @param fd descriptor which allow reading.
     * @param context structure for fd maintenance
     */
    void
    handle_read_(int fd, DescriptorActionContext& context) noexcept;

    /**
     * Translate system callbacks to class method handle_read_.
     * @param fd file descriptor
     * @param type type of fd
     * @param arg supplementary info share when event registered.
     */
    static
    void
    read_callback_(int fd, short type, void* arg) noexcept;

    /**
     * Calls when anyone writes data to termination pipe.
     * @param fd file descriptor
     * @param type type of fd
     * @param arg supplementary info share when event registered.
     */
    static
    void
    terminate_callback_(int fd, short type, void* arg) noexcept;

    /**
     * Called periodically.
     * @param fd file descriptor
     * @param type type of fd
     * @param arg supplementary info share when event registered.
     */
    static
    void
    periodic_callback_(int fd, short type, void* arg) noexcept;

    typedef std::vector<DescriptorActionContext> ReadContexts;

    static const Time PERIOD;

    const size_t DESCRIPTORS_COUNT_;
    const size_t BUFFERS_LENGTH_;
    const bool FULL_LINES_ONLY_;
    ReadContexts read_contexts_;
    size_t closed_descriptors_;
    event_base* base_;
    NonBlockingReadPipe termination_pipe_;
    event termination_;
    event periodic_;
  };

  /**
   * Callback for ActiveDescriptorListener
   */
  class ActiveDescriptorListenerCallback :
    public DescriptorListenerCallbackTempl<ActiveDescriptorListener,
      ActiveDescriptorListener_var>
  {
  public:
    /**
     * Destructor
     */
    virtual
    ~ActiveDescriptorListenerCallback() noexcept;

    /**
     * Calls deactivate_object() for the listener.
     */
    virtual
    void
    on_all_closed() noexcept;
  };

  typedef std::shared_ptr<ActiveDescriptorListenerCallback>
    ActiveDescriptorListenerCallback_var;

  /**
   * Hangs on descriptors in separate thread.
   * Call ActiveDescriptorListenerCallback callbacks,
   * when actions occurs on descriptors.
   */
  class ActiveDescriptorListener:
    public ActiveObjectCommonImpl,
    public std::enable_shared_from_this<ActiveDescriptorListener>
  {
  public:
    /**
     * In particular construct finish events.
     * @param callback reporting errors and actions callback.
     * @param descriptors file descriptors, we will read data from them and
     * call callbacks when data has been got.
     * @param dscs_amount number of file descriptors.
     * @param buffers_size buffer size for each descriptor, used to read data.
     * Cannot be 0.
     * @param full_lines_only switch on buffering mode, false mean
     * immediately call data_ready() callback.
     */
    ActiveDescriptorListener(
      ActiveDescriptorListenerCallback_var callback,
      const int* descriptors,
      size_t dscs_amount,
      size_t buffers_size = 4096,
      bool full_lines_only = false)
      /*throw (Gears::Exception)*/;

    /**
     * Destructor check active state and stop object if require.
     */
    virtual
    ~ActiveDescriptorListener() noexcept;

  private:
    class ListenerJob :
      public SingleJob,
      private DescriptorListener
    {
    public:
      ListenerJob(
        ActiveDescriptorListenerCallback_var callback,
        const int* descriptors,
        size_t number_of_descriptors,
        size_t buffers_size,
        bool full_lines_only)
        /*throw (Gears::Exception)*/;

      virtual
      ~ListenerJob() noexcept;

      void
      active_listener(
        ActiveDescriptorListener_var active_listener)
        noexcept;

      virtual void
      work() noexcept;

      virtual void
      terminate() noexcept;

    private:
      /**
       * Implement delegation calls from DLCallback
       * to ActiveDLCallback.
       */
      class DLCAdapter: public DescriptorListenerCallback
      {
      public:
        /**
         * @param active_listener active object of listener for
         * delegation calls * from DLCallback to ActiveDLCallback.
         * Must be != 0.
         * @param active_callback adapting to DLCallback ActiveDLCallback.
         * Must be != 0.
         */
        DLCAdapter(ActiveDescriptorListenerCallback_var active_callback)
          noexcept;

        /**
         * protected destructor because reference counting object.
         */
        virtual
        ~DLCAdapter() noexcept;

        void
        active_listener(ActiveDescriptorListener_var active_listener)
          noexcept;

        /**
         * @param listener pointer to object which called callback method.
         * @param fd file descriptor which was the cause of event.
         * @param fd_index index fd in original array of descriptors, used for
         * listener construction.
         * @param str string with data, not zero terminated.
         * @param size length for data string.
         */
        virtual
        void
        on_data_ready(int fd, size_t fd_index, const char* str, size_t size)
          noexcept;

        /**
         * @param listener pointer to object which called callback method.
         * @param fd descriptor that has been closed or read fails.
         * @param fd_index index fd in original array of descriptors, used
         * for listener construction.
         * @param error 0 if someone closed descriptor, non zero
         * errno value if read() failed.
         */
        virtual
        void
        on_closed(int fd, size_t fd_index, int error) noexcept;

        /**
         * Call when all descriptors used for DescriptorListener
         * creation closed. Excluding termination descriptor.
         * @param listener pointer to object that call callback.
         */
        virtual
        void
        on_all_closed() noexcept;

        /**
         * Sink for Active object errors.
         * @param object calling Active object.
         * @param severity severity for trouble.
         * @param description text that describe trouble.
         */
        virtual
        void
        report_error(Severity severity,
          const Gears::SubString& description,
          const char* error_code = 0) noexcept;

      private:
        ActiveDescriptorListenerCallback_var active_callback_;
      };

      typedef std::shared_ptr<DLCAdapter> DLCAdapter_var;
    };

    typedef std::shared_ptr<ListenerJob> ListenerJob_var;
  };

  class ExecuteAndListenCallback :
    public virtual DescriptorListenerCallback
  {
  public:
    virtual
    ~ExecuteAndListenCallback() noexcept;

    virtual
    void
    set_pid(pid_t pid) noexcept;
  };

  typedef std::shared_ptr<ExecuteAndListenCallback>
    ExecuteAndListenCallback_var;

  /**
   * Pass some descriptors numbers that we know program will write
   * to. Not necessarily that the descriptors were open.
   * We avoid possible clash between parent and child.
   *
   * @param callback Callback to be notified about data actions.
   * @param program_name The name for the process to be executed.
   * @param argv array of command line parameters execvp compatible.
   * @param descriptors_amount number of descriptors to redefine.
   * @param descriptors array of descriptors to redefine.
   * @param redirect_descriptors_amount number of descriptors to redirect
   * @param redirect_descriptors array of descriptors to redirect to /dev/null
   * @param listener_buffers_size buffer size for each descriptor,
   * used to read data. Cannot be 0.
   * @param listener_full_lines_only switch on buffering mode, false mean
   * immediately call data_ready() callback.
   * @param error_pipe create additional pipe for child error reporting
   * @return child termination status.
   */
  int
  execute_and_listen(
    ExecuteAndListenCallback_var callback,
    const char* program_name, char* const argv[],
    size_t descriptors_amount, const int* descriptors,
    size_t redirect_descriptors_amount = 0,
    const int* redirect_descriptors = 0,
    size_t listener_buffers_size = 4096,
    bool listener_full_lines_only = false, bool error_pipe = false)
    /*throw (Gears::Exception)*/;
}

//
// INLINES
//

namespace Gears
{
  //
  // DescriptorListenerCallbackTempl class
  //
  template <typename Listener, typename ListenerHolder>
  DescriptorListenerCallbackTempl<Listener, ListenerHolder>::
    DescriptorListenerCallbackTempl() /*throw (Gears::Exception)*/
    : listener_(ListenerHolder())
  {}

  template <typename Listener, typename ListenerHolder>
  DescriptorListenerCallbackTempl<Listener, ListenerHolder>::
    ~DescriptorListenerCallbackTempl() noexcept
  {}

  template <typename Listener, typename ListenerHolder>
  void
  DescriptorListenerCallbackTempl<Listener, ListenerHolder>::listener(
    ListenerHolder new_listener) noexcept
  {
    listener_ = std::move(new_listener);
  }

  template <typename Listener, typename ListenerHolder>
  Listener*
  DescriptorListenerCallbackTempl<Listener, ListenerHolder>::listener()
    noexcept
  {
    return &*listener_;
  }

  template <typename Listener, typename ListenerHolder>
  void
  DescriptorListenerCallbackTempl<Listener, ListenerHolder>::on_closed(
    int /*fd*/, size_t /*fd_index*/, int /*error*/) noexcept
  {}

  template <typename Listener, typename ListenerHolder>
  void
  DescriptorListenerCallbackTempl<Listener, ListenerHolder>::on_periodic()
    noexcept
  {}

  //
  // DescriptorListenerCallback class
  //
  inline
  DescriptorListenerCallback::~DescriptorListenerCallback() noexcept
  {}

  //
  // ActiveDescriptorListenerCallback class
  //
  inline
  ActiveDescriptorListenerCallback::~ActiveDescriptorListenerCallback()
    noexcept
  {}

  //
  // ExecuteAndListenCallback class
  //
  inline
  ExecuteAndListenCallback::~ExecuteAndListenCallback() noexcept
  {}
}

#endif
