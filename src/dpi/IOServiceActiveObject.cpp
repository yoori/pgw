#include <deque>

#include "IOServiceActiveObject.hpp"

namespace dpi
{
  struct IOServiceActiveObject::Impl
  {
    boost::asio::io_service io_service;
    std::deque<std::thread> thread_pool;
    std::unique_ptr<boost::asio::io_service::work> io_service_work;
  };

  IOServiceActiveObject::IOServiceActiveObject(unsigned int threads_count)
    : threads_count_(threads_count),
      impl_(std::make_unique<Impl>())
  {}

  IOServiceActiveObject::~IOServiceActiveObject() noexcept
  {}

  boost::asio::io_service& IOServiceActiveObject::io_service()
  {
    return impl_->io_service;
  }

  void IOServiceActiveObject::activate_object_()
  {
    std::cout << "IOServiceActiveObject::activate_object_" << std::endl;

    // make sure that io_service run() will not return
    impl_->io_service_work.reset(new boost::asio::io_service::work(impl_->io_service));

    // start running of tasks
    for (int thread_index = 0; thread_index < threads_count_; ++thread_index)
    {
      impl_->thread_pool.emplace_back(std::thread(
        [this]
        {
          std::cout << "to io_service run" << std::endl;
          impl_->io_service.run();
          std::cout << "from io_service run" << std::endl;
        }
      ));
    }
  }

  void IOServiceActiveObject::deactivate_object_()
  {
    impl_->io_service.stop();
  }

  void IOServiceActiveObject::wait_object_()
  {
    for (auto& thread : impl_->thread_pool)
    {
      thread.join();
    }

    impl_->thread_pool.clear();
  }
}
