#ifndef GEARS_DESCRIPTORS_HPP_
#define GEARS_DESCRIPTORS_HPP_

#include <unistd.h>
#include <fcntl.h>
#include <memory>

#include <gears/Errno.hpp>
//#include <Gears/Function.hpp>
#include <gears/OutputMemoryStream.hpp>

namespace Gears
{
  /**
   * Pipe operations
   */
  class Pipe
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(Errno, Exception);
    DECLARE_EXCEPTION(ConnectionClosed, Exception);

    /**
     * Creates pipe
     */
    Pipe() /*throw (Gears::Exception, Exception)*/;
    /**
     * Closes both ends of the pipe
     */
    ~Pipe() noexcept;

    /**
     * Read descriptor
     * @return read descriptor
     */
    int
    read_descriptor() const noexcept;
    /**
     * Write descriptor
     * @return write descriptor
     */
    int
    write_descriptor() const noexcept;

    /**
     * Performs a single read operation from the pipe
     * @param buf buffer for read data
     * @param size maximum read size
     * @return see read(2)
     */
    ssize_t
    read(void* buf, size_t size) noexcept;

    /**
     * Tries to read the exact amount of data.
     * Throws an exception if fails.
     * @param buf buffer for read data
     * @param size read size
     */
    void
    read_n(void* buf, size_t size) /*throw (Exception)*/;

    /**
     * Performs a single write operation into the pipe
     * @param buf buffer with write data
     * @param size buffer size
     * @return see write(2)
     */
    ssize_t
    write(const void* buf, size_t size) noexcept;

    /**
     * Tries to write the exact amount of data.
     * Throws an exception if fails.
     * @param buf buffer with write data
     * @param size write size
     */
    void
    write_n(const void* buf, size_t size) /*throw (Exception)*/;

    /**
     * Writes a single character into the pipe ignoring EINTRs
     * @param ch character to write
     * @return see write(2)
     */
    ssize_t
    signal(char ch = '\0') noexcept;

  protected:
    template <typename Functor>
    void
    act_n_(Functor func, int fd, void* buf, ssize_t size) /*throw (Exception)*/;

  private:
    int pipe_[2];
  };

  typedef std::shared_ptr<Pipe> Pipe_var;

  /**
   * Pipe with non-blocking read end.
   */
  class NonBlockingReadPipe : protected Pipe
  {
  public:
    using Pipe::Exception;
    using Pipe::Errno;
    using Pipe::ConnectionClosed;

    /**
     * Unblocks the read end
     */
    NonBlockingReadPipe() /*throw (Gears::Exception, Exception)*/;

    using Pipe::read_descriptor;
    using Pipe::write_descriptor;
    using Pipe::read;
    using Pipe::write;
    using Pipe::write_n;
    using Pipe::signal;
  };

  /**
   * Descriptor to /dev/null
   */
  class DevNull : private Uncopyable
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    DevNull() /*throw (Gears::Exception, Exception)*/;
    ~DevNull() noexcept;

    int
    fd() noexcept;

  private:
    int fd_;
  };

  /**
   * Sets FD_CLOEXEC on the specified descriptor
   * @param fd descriptor to tune
   * @return 0 for success, negative for fcntl error
   */
  int
  set_cloexec(int fd) noexcept;
}

//
// INLINES
//

namespace Gears
{
  //
  // Pipe class
  //

  inline
  Pipe::Pipe() /*throw (Gears::Exception, Exception)*/
  {
    static const char* FNE = "Pipe::Pipe()";

    if (pipe(pipe_) < 0)
    {
      Gears::throw_errno_exception<Exception>(FNE, "failed to create pipe");
    }
  }

  inline
  Pipe::~Pipe() noexcept
  {
    close(pipe_[1]);
    close(pipe_[0]);
  }

  inline
  int
  Pipe::read_descriptor() const noexcept
  {
    return pipe_[0];
  }

  inline
  int
  Pipe::write_descriptor() const noexcept
  {
    return pipe_[1];
  }

  inline
  ssize_t
  Pipe::read(void* buf, size_t size) noexcept
  {
    return ::read(read_descriptor(), buf, size);
  }

  template <typename Functor>
  void
  Pipe::act_n_(Functor func, int fd, void* buf, ssize_t size)
    /*throw (Exception)*/
  {
    static const char* FUN = "Pipe::act_n_()";
    static const char* FNE = "Pipe::act_n_(): ";

    do
    {
      ssize_t res = func(fd, buf, size);

      if (res < 0)
      {
        if (errno == EINTR)
        {
          continue;
        }

        Gears::throw_errno_exception<Errno>(FNE, "operation failed");
      }

      if (!res)
      {
        ErrorStream ostr;
        ostr << FUN << ": other end of the pipe is closed";
        throw ConnectionClosed(ostr.str());
      }


      size -= res;
      buf = static_cast<char*>(buf) + res;
    }
    while (size);
  }

  inline
  void
  Pipe::read_n(void* buf, size_t size) /*throw (Exception)*/
  {
    act_n_(::read, read_descriptor(), buf, size);
  }

  inline
  ssize_t
  Pipe::write(const void* buf, size_t size) noexcept
  {
    return ::write(write_descriptor(), buf, size);
  }

  inline
  void
  Pipe::write_n(const void* buf, size_t size) /*throw (Exception)*/
  {
    act_n_(::write, write_descriptor(), const_cast<void*>(buf), size);
  }

  inline
  ssize_t
  Pipe::signal(char ch) noexcept
  {
    ssize_t result;
    while ((result = write(&ch, 1)) < 0 && errno == EINTR)
    {
    }
    return result;
  }


  //
  // NonBlockingPipe class
  //

  inline
  NonBlockingReadPipe::NonBlockingReadPipe()
    /*throw (Gears::Exception, Exception)*/
  {
    static const char* FNE = "NonBlockingReadPipe::NonBlockingReadPipe(): ";

    int flags = fcntl(read_descriptor(), F_GETFL);
    if (flags == -1 ||
      fcntl(read_descriptor(), F_SETFL, flags | O_NONBLOCK) == -1)
    {
      Gears::throw_errno_exception<Exception>(FNE, "fcntl failure");
    }
  }

  //
  // DevNull class
  //

  inline
  DevNull::DevNull() /*throw (Gears::Exception, Exception)*/
  {
    fd_ = open("/dev/null", O_RDWR);
    if (fd_ < 0)
    {
      Gears::throw_errno_exception<Exception>(
        "DevNull::DevNull(): ", "Failed to open /dev/null");
    }
  }

  inline
  DevNull::~DevNull() noexcept
  {
    close(fd_);
  }

  inline
  int
  DevNull::fd() noexcept
  {
    return fd_;
  }


  //

  inline
  int
  set_cloexec(int fd) noexcept
  {
    int flags = fcntl(fd, F_GETFD);
    return flags < 0 ? flags : fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  }
}

#endif
