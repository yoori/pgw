#pragma once

#include <thread>

#include <boost/asio/io_service.hpp>

#include <gears/ActiveObject.hpp>

namespace dpi
{
  class IOServiceActiveObject: public Gears::SimpleActiveObject
  {
  public:
    IOServiceActiveObject();

    boost::asio::io_service& io_service();

  protected:
    void activate_object_() override;

    void deactivate_object_() override;

    void wait_object_() override;

    void loop_();

  protected:
    boost::asio::io_service io_service_;
    std::unique_ptr<std::thread> thread_;
  };
}
