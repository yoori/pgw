#pragma once

#include <string>
#include <optional>
#include <vector>
#include <mutex>

#include <Diameter/Packet.hpp>

#include <gears/Exception.hpp>

#include "Logger.hpp"
#include "NetworkUtils.hpp"
#include "BaseConnection.hpp"

namespace dpi
{
  // SCTPConnection
  class SCTPConnection: public BaseConnection
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(NetworkError, Exception);
    DECLARE_EXCEPTION(ConnectionClosedOnRead, NetworkError);

    struct Endpoint
    {
      Endpoint() {};

      Endpoint(std::string host_val, int port_val)
        : host(std::move(host_val)), port(port_val)
      {}

      std::string host;
      int port = 0;
    };

  public:
    SCTPConnection(
      LoggerPtr logger,
      std::vector<Endpoint> local_endpoints,
      std::vector<Endpoint> connect_endpoints,
      std::function<void(SCTPConnection&)> init_fun = [](SCTPConnection&) {}
    );

    void connect() override;

    void send_packet(const ByteArray& send_packet) override;

    std::vector<unsigned char> read_bytes(unsigned long size) override;

    void close() override;

    void stream_send_packet(
      unsigned int stream_index, const ByteArray& send_packet);

    std::vector<unsigned char> stream_read_bytes(
      unsigned int stream_index, unsigned long size);

    void stream_close(unsigned int stream_index);

  private:
    struct ConnectionHolder
    {
      int socket_fd;
    };

  private:
    static bool is_connected_(int socket_fd);

    static void send_packet_(int socket_fd, const ByteArray& send_packet);

    static void stream_send_packet_(
      unsigned int stream_index,
      int socket_fd,
      const ByteArray& send_packet);

    static std::vector<unsigned char>
    read_bytes_(int socket_fd, unsigned long size);

    std::vector<unsigned char> stream_read_bytes_(
      int socket_fd,
      unsigned int stream_index,
      unsigned long size);

    ConnectionHolder socket_init_();

    static void socket_close_(int socket_fd);

    static void fill_addr_(struct sockaddr_in& res, const Endpoint& endpoint);

  private:
    const bool keep_open_connection_;

    LoggerPtr logger_;
    std::vector<Endpoint> local_endpoints_;
    std::vector<Endpoint> connect_endpoints_;
    std::function<void(SCTPConnection&)> init_fun_;

    std::optional<ConnectionHolder> connection_holder_;

    std::unordered_map<unsigned int, std::vector<unsigned char>> stream_buffers_;
  };

  using SCTPConnectionPtr = std::shared_ptr<SCTPConnection>;

  // SCTPStreamConnection
  class SCTPStreamConnection: public BaseConnection
  {
  public:
    SCTPStreamConnection(SCTPConnectionPtr connection, unsigned int stream_index);

    void connect() override;

    void send_packet(const ByteArray& send_packet) override;

    std::vector<unsigned char> read_bytes(unsigned long size) override;

    void close() override;

  private:
    SCTPConnectionPtr sctp_connection_;
    unsigned int stream_index_;
  };
}
