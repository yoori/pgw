#ifndef LOGGER_ACTIVE_OBJECT_CALLBACK_HPP
#define LOGGER_ACTIVE_OBJECT_CALLBACK_HPP

#include "ActiveObject.hpp"
#include "Logger.hpp"


namespace Gears
{
  /**
   * Adapter for logger into reference countable callback.
   * Forward error reports into logger.
   */
  class ActiveObjectCallbackImpl :
    public virtual ActiveObjectCallback
  {
  public:
    explicit
    ActiveObjectCallbackImpl(
      Logger_var logger = Logger_var(),
      const char* message_prefix = "ActiveObject",
      const char* aspect = 0,
      const char* code = 0) noexcept;

    virtual
    ~ActiveObjectCallbackImpl() noexcept = default;

  protected:
    virtual
    void
    report_error(Severity severity, const Gears::SubString& description,
      const char* code = 0) noexcept;

    virtual
    Logger_var
    logger() const noexcept;

    virtual
    const char*
    message_prefix() const noexcept;

    virtual
    const char*
    aspect() const noexcept;

    virtual
    const char*
    code(const char* error_code) const noexcept;

  private:
    Logger_var logger_;
    const char* message_prefix_;
    const char* aspect_;
    const char* code_;
  };

  typedef std::shared_ptr<ActiveObjectCallbackImpl>
    ActiveObjectCallbackImpl_var;

  /**
   * Simply represent linked pair of Logger & ActiveObjectCallback
   * with ability to change logger at runtime
   */
  class LoggerCallbackHolder
  {
  public:
    /*
     * Construct LoggerCallbackHolder
     * @param logger is initial logger will be used
     * @param message_prefix for callback
     * @param aspect for callback
     * @param code for callback
     */
    LoggerCallbackHolder(
      Logger_var logger,
      const char* message_prefix,
      const char* aspect,
      const char* code) /*throw (Gears::Exception)*/;

    /*
     * Get stored callback
     * @return stored callback
     */
    Gears::ActiveObjectCallback_var
    callback() noexcept;

    /*
     * Get stored logger
     * @return stored logger
     */
    Logger_var
    logger() const noexcept;

    /*
     * Set stored logger
     * @param new_logger is logger to store
     */
    void
    logger(Logger_var new_logger) noexcept;

  protected:
    mutable LoggerHolder_var logger_holder_;
    ActiveObjectCallback_var callback_;
  };

  typedef std::shared_ptr<LoggerCallbackHolder>
    LoggerCallbackHolder_var;
}

//
// INLINES
//

namespace Gears
{
  //
  // ActiveObjectCallback class
  //

  inline
  ActiveObjectCallbackImpl::ActiveObjectCallbackImpl(
    Gears::Logger_var logger,
    const char* message_prefix,
    const char* aspect,
    const char* code) noexcept
    : logger_(logger),
      message_prefix_(message_prefix),
      aspect_(aspect),
      code_(code)
  {}


  //
  // LoggerCallbackHolder class
  //

  inline
  LoggerCallbackHolder::LoggerCallbackHolder(
    Logger_var logger,
    const char* message_prefix,
    const char* aspect,
    const char* code)
    /*throw (Gears::Exception)*/
    : logger_holder_(new LoggerHolder(logger)),
      callback_(new ActiveObjectCallbackImpl(logger_holder_,
        message_prefix, aspect, code))
  {}

  inline
  Gears::ActiveObjectCallback_var
  LoggerCallbackHolder::callback() noexcept
  {
    return callback_;
  }

  inline
  Logger_var
  LoggerCallbackHolder::logger() const noexcept
  {
    return logger_holder_;
  }

  inline
  void
  LoggerCallbackHolder::logger(Logger_var new_logger) noexcept
  {
    logger_holder_->logger(new_logger);
  }
}

#endif
