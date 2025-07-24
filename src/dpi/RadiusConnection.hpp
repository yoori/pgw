#pragma once

#include <netinet/in.h>
#include <memory>
#include <string>
#include <cstdint>
#include <thread>

#include <gears/ActiveObject.hpp>

namespace dpi
{
  class RadiusConnection: public Gears::SimpleActiveObject
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(NetworkError, Exception);

    struct DisconnectRequest
    {
      std::string session_id;
      std::string msisdn;
      uint32_t framed_ip_address = 0;
    };

  public:
    RadiusConnection(
      const std::string& host,
      unsigned int port,
      const std::string& secret);

    void send_disconnect(const DisconnectRequest& request);

  protected:
    struct ConnectionHolder;

    using ConnectionHolderPtr = std::shared_ptr<ConnectionHolder>;

  protected:
    void
    close_();

    void
    close_(ConnectionHolder& connection_holder);

    ConnectionHolderPtr
    connect_if_not_connected_();

    ConnectionHolderPtr
    connect_();

    void
    process_input_packets_(int socket);

    void
    activate_object_() override;

    void
    deactivate_object_() override;

    void
    wait_object_() override;

  private:
    const std::string connect_host_;
    const unsigned int connect_port_;
    const std::string secret_;

    std::mutex connect_lock_; //< lock when connect in progress
    std::mutex connection_holder_lock_;
    ConnectionHolderPtr connection_holder_;
  };

  using RadiusConnectionPtr = std::shared_ptr<RadiusConnection>;
}
