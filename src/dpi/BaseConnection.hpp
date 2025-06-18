#pragma once

#include <memory>
#include <mutex>

#include <Diameter/Packet.hpp>

namespace dpi
{
  // BaseConnection
  class BaseConnection
  {
  public:
    class Lock
    {
    public:
      Lock(BaseConnection* connection)
        : locker_(std::make_unique<std::unique_lock<std::mutex>>(connection->lock_)),
          connection_(connection)
      {}

      BaseConnection* operator->()
      {
        return connection_;
      }

      BaseConnection* get()
      {
        return connection_;
      }

    private:
      std::unique_ptr<std::unique_lock<std::mutex>> locker_;
      BaseConnection* connection_;
    };

  public:
    Lock lock();

    virtual void connect() = 0;

    virtual void send_packet(const ByteArray& send_packet) = 0;

    virtual std::vector<unsigned char> read_bytes(unsigned long size) = 0;

    virtual void close() = 0;

  protected:
    std::mutex lock_;
  };

  using BaseConnectionPtr = std::shared_ptr<BaseConnection>;
}

namespace dpi
{
  // BaseConnection impl
  inline BaseConnection::Lock
  BaseConnection::lock()
  {
    return Lock(this);
  }
}
