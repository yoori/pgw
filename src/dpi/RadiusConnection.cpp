#include <netinet/in.h>
#include <arpa/inet.h>

#include "radproto/attribute_types.h"
#include "packet.h"

#include "RadiusConnection.hpp"

namespace dpi
{
  struct RadiusConnection::ConnectionHolder
  {
    int socket = 0;
    struct sockaddr_in server_addr;
    std::unique_ptr<std::thread> process_input_packets_thread;
  };

  RadiusConnection::RadiusConnection(
    const std::string& host,
    unsigned int port,
    const std::string& secret)
    : connect_host_(host),
      connect_port_(port),
      secret_(secret)
  {}

  void
  RadiusConnection::send_disconnect(const DisconnectRequest& request)
  {
    // fill send buffer
    std::vector<RadProto::Attribute*> attributes;
    attributes.emplace_back(new RadProto::String(44, "b9ae8335020cbf5c")); //< Acct-Session-Id
    attributes.emplace_back(new RadProto::String(RadProto::USER_NAME, "79662660021"));
    attributes.emplace_back(new RadProto::IpAddress(8, {10, 243, 64, 1})); //< Framed-IP-Address
    std::vector<RadProto::VendorSpecific> vendor_attributes;

    RadProto::Packet send_packet(
      40, //< Disconnect-Request,
      128, //< id
      attributes,
      vendor_attributes
    );

    auto send_buffer = send_packet.makeSendBuffer(secret_);

    auto connection_holder = connect_if_not_connected_();
    assert(connection_holder);

    int res = ::sendto(
      connection_holder->socket,
      &send_buffer[0],
      send_buffer.size(),
      MSG_CONFIRM,
      (const struct sockaddr*)&connection_holder->server_addr,
      sizeof(connection_holder->server_addr));

    if (res < 0)
    {
      throw NetworkError(std::string("Send failed, errno = ") + std::to_string(errno));
    }
  }

  void
  RadiusConnection::activate_object_()
  {
  }

  RadiusConnection::ConnectionHolderPtr
  RadiusConnection::connect_if_not_connected_()
  {
    std::unique_lock<std::mutex> lock(connect_lock_);

    if (!active())
    {
      throw Exception(std::string("Trying to use connection on non active object"));
    }

    {
      std::unique_lock<std::mutex> lock(connection_holder_lock_);
      if (connection_holder_)
      {
        return connection_holder_;
      }
    }

    // connection_holder_ is null
    return connect_();
  }

  RadiusConnection::ConnectionHolderPtr
  RadiusConnection::connect_()
  {
    auto connection_holder = std::make_shared<ConnectionHolder>();

    if ((connection_holder->socket = ::socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      throw NetworkError(std::string("Can't create socket, errno = ") + std::to_string(errno));
    }

    ::memset(&connection_holder->server_addr, 0, sizeof(connection_holder->server_addr));
    connection_holder->server_addr.sin_family = AF_INET;
    connection_holder->server_addr.sin_port = ::htons(connect_port_);
    if (::inet_aton(connect_host_.c_str(), &connection_holder->server_addr.sin_addr) == 0)
    {
      throw NetworkError(std::string("Can't parse connect host: ") + connect_host_);
    }

    // start processing thread
    connection_holder->process_input_packets_thread = std::make_unique<std::thread>(
      [this, socket = connection_holder->socket](){
        this->process_input_packets_(socket);
      }
    );

    ConnectionHolderPtr prev_connection_holder;

    {
      std::unique_lock<std::mutex> lock(connection_holder_lock_);
      prev_connection_holder = connection_holder_;
      connection_holder_ = connection_holder;
    }

    if (prev_connection_holder)
    {
      // previous connection holder isn't null - close it
      close_(*prev_connection_holder);
    }

    return connection_holder;
  }

  void
  RadiusConnection::close_()
  {
    // close socket for hang up reading thread
    ConnectionHolderPtr connection_holder;

    {
      std::unique_lock<std::mutex> lock(connection_holder_lock_);
      connection_holder_.swap(connection_holder);
    }

    if (connection_holder)
    {
      close_(*connection_holder);
    }
  }

  void
  RadiusConnection::close_(ConnectionHolder& connection_holder)
  {
    ::close(connection_holder.socket);

    if (connection_holder.process_input_packets_thread)
    {
      connection_holder.process_input_packets_thread->join();
    }
  }

  void
  RadiusConnection::deactivate_object_()
  {
    std::unique_lock<std::mutex> lock(connect_lock_); //< connect can't be done here or after (or wait when it will be finished)

    ConnectionHolderPtr connection_holder;

    {
      std::unique_lock<std::mutex> lock(connection_holder_lock_);
      connection_holder = connection_holder_;
    }

    if (connection_holder)
    {
      ::close(connection_holder->socket);
    }
  }

  void
  RadiusConnection::wait_object_()
  {
    ConnectionHolderPtr connection_holder;

    {
      std::unique_lock<std::mutex> lock(connection_holder_lock_);
      connection_holder = connection_holder_;
    }

    if (connection_holder)
    {
      connection_holder->process_input_packets_thread->join();
    }
  }

  void
  RadiusConnection::process_input_packets_(int socket)
  {
    unsigned char read_buf[64000];
    struct sockaddr_in server_addr;
    socklen_t addr_len;

    try
    {
      while (active())
      {
        int res = ::recvfrom(
          socket,
          read_buf,
          sizeof(read_buf),
          MSG_WAITALL,
          (struct sockaddr*)&server_addr,
          &addr_len);

        if (res == -1)
        {
          if (errno == EBADF || errno == EINTR)
          {
            // socket closed - reading interrupted
            break;
          }
          else
          {
            // some error on socket
            throw NetworkError(std::string("errno = ") + std::to_string(errno));
          }
        }

        // process input packets
        std::cout << "Input packet received (size = " << res << ")" << std::endl;
      }
    }
    catch(const Gears::Exception& ex)
    {
      std::cerr << "RadiusConnection: error in socket reading loop: " << ex.what() << std::endl;
    }
  }
}
