#include "IOServiceActiveObject.hpp"

namespace dpi
{
  IOServiceActiveObject::IOServiceActiveObject()
  {}

  boost::asio::io_service& IOServiceActiveObject::io_service()
  {
    return io_service_;
  }

  void IOServiceActiveObject::activate_object_()
  {
    if (!thread_)
    {
      thread_ = std::make_unique<std::thread>(
        [this] {
          this->loop_();
        }
      );
    }
  }

  void IOServiceActiveObject::deactivate_object_()
  {
    io_service_.stop();
  }

  void IOServiceActiveObject::wait_object_()
  {
    if (thread_)
    {
      thread_->join();
      thread_.reset();
    }
  }

  void IOServiceActiveObject::loop_()
  {
    io_service_.run();
  }
}
