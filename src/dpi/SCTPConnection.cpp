#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/sctp.h>

#include <iostream>

#include "SCTPConnection.hpp"

namespace dpi
{
  // Connection impl
  SCTPConnection::SCTPConnection(
    dpi::LoggerPtr logger,
    std::vector<Endpoint> local_endpoints,
    std::vector<Endpoint> connect_endpoints,
    std::function<void(SCTPConnection&)> init_fun)
    : keep_open_connection_(true),
      logger_(std::move(logger)),
      local_endpoints_(std::move(local_endpoints)),
      connect_endpoints_(std::move(connect_endpoints)),
      init_fun_(init_fun)
  {
  }

  void
  SCTPConnection::connect()
  {
    try
    {
      if (!connection_holder_.has_value())
      {
        connection_holder_ = socket_init_();
        return;
      }
    }
    catch(const Gears::Exception&)
    {
      connection_holder_ = std::nullopt;
      throw;
    }

    // check connection
    bool is_connected = is_connected_(connection_holder_->socket_fd);

    //std::cout << "to check connection: is_connected = " << is_connected << std::endl;

    if (!is_connected)
    {
      socket_close_(connection_holder_->socket_fd);
      connection_holder_ = std::nullopt;
      connection_holder_ = socket_init_();
    }
  }

  bool
  SCTPConnection::is_connected_(int socket_fd)
  {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(socket_fd, &readfds);

    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0; // non-blocking select

    int result = select(socket_fd + 1, &readfds, nullptr, nullptr, &timeout);

    if (result > 0 && FD_ISSET(socket_fd, &readfds))
    {
      char buffer[1];
      ssize_t bytes_received = ::recv(socket_fd, buffer, sizeof(buffer), MSG_PEEK);

      if (bytes_received == 0)
      {
        return false; // connection closed
      }
      else if (bytes_received == -1)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          return true; // not closed, try again later
        }
        else
        {
          return false; // error, treat as closed
        }
      }
    }

    return true; // Not closed
  }

  void
  SCTPConnection::send_packet(const ByteArray& send_packet)
  {
    try
    {
      // std::cout << "SCTPConnection::send_packet: size = " << send_packet.size() << std::endl;
      if (!connection_holder_.has_value())
      {
        connection_holder_ = socket_init_();
      }
      
      send_packet_(connection_holder_->socket_fd, send_packet);
    }
    catch(const Gears::Exception&)
    {
      connection_holder_ = std::nullopt;
      throw;
    }
  }

  void
  SCTPConnection::stream_send_packet(unsigned int stream_index, const ByteArray& send_packet)
  {
    try
    {
      if (!connection_holder_.has_value())
      {
        connection_holder_ = socket_init_();
      }
      
      stream_send_packet_(stream_index, connection_holder_->socket_fd, send_packet);
    }
    catch(const Gears::Exception&)
    {
      connection_holder_ = std::nullopt;
      throw;
    }
  }

  void
  SCTPConnection::send_packet_(int socket_fd, const ByteArray& send_packet)
  {
    if (socket_fd <= 0)
    {
      throw NetworkError("Try to write into non opened socket");
    }

    //int res = ::write(socket_fd, send_packet.data(), send_packet.size());
    int res = ::sctp_sendmsg(
      socket_fd,
      send_packet.data(),
      send_packet.size(),
      0, // to
      0, // tolen
      0, // ppid
      0, // flags
      1, // stream index
      0, // ttl
      0  // context
    );

    if (res < send_packet.size())
    {
      socket_close_(socket_fd);
      throw NetworkError("Write failed");
    }

    //std::cout << "[DEBUG] From send diameter packet (bytes = " << send_packet.size() <<
    //  ")" << std::endl;
  }

  void
  SCTPConnection::stream_close(unsigned int stream_index)
  {
    if (connection_holder_.has_value() && connection_holder_->socket_fd > 0)
    {
      //std::cout << "stream_close: stream_index = " << stream_index <<
      //  ", socket_fd = " << connection_holder_->socket_fd << std::endl;
      //::close(connection_holder_->socket_fd);

      ::sctp_sendmsg(
        connection_holder_->socket_fd,
        NULL,
        0,
        0, // to
        0, // tolen
        0, // ppid
        SCTP_ABORT | SCTP_SENDALL | SCTP_EOF, // flags
        stream_index, // stream index
        0, // ttl
        0  // context
      );
    }
  }

  void
  SCTPConnection::stream_send_packet_(unsigned int stream_index, int socket_fd, const ByteArray& send_packet)
  {
    if (socket_fd <= 0)
    {
      throw NetworkError("Try to write into non opened socket");
    }

    int res = ::sctp_sendmsg(
      socket_fd,
      send_packet.data(),
      send_packet.size(),
      0, // to
      0, // tolen
      0, // ppid
      0, // flags
      stream_index, // stream index
      0, // ttl
      0  // context
    );

    if (res < send_packet.size())
    {
      socket_close_(socket_fd);
      throw NetworkError("Write failed");
    }

    //std::cout << "[DEBUG] From send diameter packet (bytes = " << send_packet.size() <<
    //  ", stream = " << stream_index << ")" << std::endl;
  }

  std::vector<unsigned char>
  SCTPConnection::stream_read_bytes(unsigned int stream_index, unsigned long size)
  {
    return stream_read_bytes_(connection_holder_->socket_fd, stream_index, size);
  }

  std::vector<unsigned char>
  SCTPConnection::stream_read_bytes_(int socket_fd, unsigned int stream_index, unsigned long size)
  {
    std::vector<unsigned char> buf(size);

    while (true)
    {
      {
        auto& stream_buf = stream_buffers_[stream_index];
        if (stream_buf.size() > size)
        {
          std::copy(stream_buf.begin(), stream_buf.begin() + size, buf.end());
          stream_buf.erase(stream_buf.begin(), stream_buf.begin() + size);
          return buf;
        }
        else if(stream_buf.size() == size)
        {
          buf.clear();
          buf.swap(stream_buf);
          return buf;
        }
      }

      sctp_sndrcvinfo sinfo;

      //std::cout << "to sctp_recvmsg: socket_fd = " << socket_fd << std::endl;

      int read_res = ::sctp_recvmsg(
        socket_fd,
        buf.data(),
        size,
        0, // from
        0, // fromlen
        &sinfo,
        0);

      //std::cout << "from sctp_recvmsg => " << read_res << ", sinfo.sinfo_stream = " << sinfo.sinfo_stream << std::endl;

      if (read_res < 0)
      {
        char error_buf[128];
        int e = errno;
        char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
        std::ostringstream ostr;
        ostr << "Diameter head read error, errno = " << e << ", message = " << error_msg;
        throw NetworkError(ostr.str());
      }
      else if (read_res == 0)
      {
        if (errno != EINPROGRESS || errno != EAGAIN)
        {
          socket_close_(socket_fd);
          throw ConnectionClosedOnRead(
            std::string("Connection closed on read, errno = ") + std::to_string(errno));
        }
      }

      auto& stream_buf = stream_buffers_[stream_index];
      stream_buf.insert(stream_buf.end(), buf.begin(), buf.end());
    }
  }

  void
  SCTPConnection::socket_close_(int socket_fd)
  {
    if (socket_fd > 0)
    {
      std::cout << "Close socket: socket_fd = " << socket_fd << std::endl;
      ::shutdown(socket_fd, SHUT_RDWR);
      ::close(socket_fd);
    }
  }

  std::vector<unsigned char>
  SCTPConnection::read_bytes(unsigned long size)
  {
    return read_bytes_(connection_holder_->socket_fd, size);
  }

  void
  SCTPConnection::close()
  {
    if (connection_holder_.has_value())
    {
      socket_close_(connection_holder_->socket_fd);
    }
  }

  std::vector<unsigned char>
  SCTPConnection::read_bytes_(int socket_fd, unsigned long size)
  {
    std::vector<unsigned char> buf(size);
    int read_pos = 0;
    while(read_pos < size)
    {
      //std::cout << "To read_bytes_: socket_fd = " << socket_fd << std::endl;
      int read_res = ::read(socket_fd, &buf[read_pos], size - read_pos);
      //std::cout << "From read_bytes_: socket_fd = " << socket_fd << ", read_res = " << read_res << std::endl;
      //std::cout << "[DEBUG] Diameter read finished (bytes = " << read_res <<
      //  "), socket_fd = " << socket_fd << std::endl;

      if (read_res < 0)
      {
        char error_buf[128];
        int e = errno;
        char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
        std::ostringstream ostr;
        ostr << "Diameter head read error, errno = " << e << ", message = " << error_msg;
        throw NetworkError(ostr.str());
      }
      else if (read_res == 0)
      {
        if (errno != EINPROGRESS || errno != EAGAIN)
        {
          socket_close_(socket_fd);
          throw ConnectionClosedOnRead(
            std::string("Connection closed on read, errno = ") + std::to_string(errno));
        }
      }

      read_pos += read_res;
    }

    return buf;
  }

  SCTPConnection::ConnectionHolder
  SCTPConnection::socket_init_()
  {
    int socket_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if(socket_fd < 0)
    {
      throw NetworkError("Cannot open socket");
    }

    int val = 1;
    ::setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));

    struct sctp_initmsg init_msg;
    ::memset(&init_msg, 0, sizeof(init_msg));
    init_msg.sinit_num_ostreams = 3;
    init_msg.sinit_max_instreams = 3;
    init_msg.sinit_max_attempts = 2;
    ::setsockopt(socket_fd, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof(init_msg));

    struct sctp_event_subscribe events;
    ::memset(&events, 0, sizeof(events));
    events.sctp_data_io_event = 1;
    events.sctp_shutdown_event = 1;
    events.sctp_peer_error_event = 1;
    ::setsockopt(socket_fd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events));

    try
    {
      // Bind local addresses
      if (!local_endpoints_.empty())
      {
        unsigned int result_local_port = local_endpoints_.begin()->port;
        unsigned int local_addr_i = 0;
        //std::cout << "SCTP local_endpoints_.size() = " << local_endpoints_.size() << std::endl;
        for (auto addr_it = local_endpoints_.begin(); addr_it != local_endpoints_.end();
          ++addr_it, ++local_addr_i)
        {
          sockaddr_in local_addr;
          fill_addr_(local_addr, *addr_it);
          local_addr.sin_port = ::htons(result_local_port);

          int res;

          if (local_addr_i == 0)
          {
            res = ::bind(socket_fd, (sockaddr*)&local_addr, sizeof(sockaddr_in));
          }
          else
          {
            res = ::sctp_bindx(socket_fd, (sockaddr*)&local_addr, 1, SCTP_BINDX_ADD_ADDR);
          }

          if (res < 0)
          {
            char error_buf[128];
            int e = errno;
            char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
            std::ostringstream ostr;
            ostr << "Cannot bind to " << addr_it->host << ":" << addr_it->port <<
              ": errno = " << e << ", message = " << error_msg;
            throw NetworkError(ostr.str());
          }

          if (local_addr_i == 0 && addr_it->port == 0)
          {
            struct sockaddr_in local_addr;
            socklen_t len = sizeof(sockaddr_in);
            res = ::getsockname(socket_fd, (sockaddr*)&local_addr, &len);

            if (res < 0)
            {
              char error_buf[128];
              int e = errno;
              char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
              std::ostringstream ostr;
              ostr << "Cannot get sock addr: errno = " << e << ", message = " << error_msg;
              throw NetworkError(ostr.str());
            }

            result_local_port = ::ntohs(local_addr.sin_port);
          }
        }
      }

      // Connect
      std::vector<struct sockaddr_in> connect_addrs(connect_endpoints_.size());
      unsigned int conn_i = 0;
      for (auto conn_it = connect_endpoints_.begin(); conn_it != connect_endpoints_.end(); ++conn_it, ++conn_i)
      {
        fill_addr_(connect_addrs[conn_i], *conn_it);
      }

      int res = ::sctp_connectx(
        socket_fd,
        (sockaddr*)&connect_addrs[0],
        connect_addrs.size(),
        NULL);

      if(res < 0)
      {
        if (errno == EINPROGRESS)
        {
          fd_set fdset;
          do
          {
            struct timeval tv;
            tv.tv_sec = 3;
            tv.tv_usec = 0;
            FD_ZERO(&fdset);
            FD_SET(socket_fd, &fdset);
            int res = ::select(socket_fd + 1, NULL, &fdset, NULL, &tv);
            if (res < 0 && errno != EINTR)
            {
              throw NetworkError("Connecting error");
            }
            else if (res > 0)
            {
              break;
            }
            else
            {
              throw NetworkError("Timeout on connection");
            }
          }
          while (true);
        }
        else
        {
          char error_buf[128];
          int e = errno;
          char* error_msg = strerror_r(e, error_buf, sizeof(error_buf));
          std::ostringstream ostr;
          ostr << "Cannot connect: errno = " << e << ", message = " << error_msg;
          throw NetworkError(ostr.str());
        }
      }
    }
    catch(...)
    {
      if (socket_fd > 0)
      {
         std::cout << "Close socket: socket_fd = " << socket_fd << std::endl;
        ::shutdown(socket_fd, SHUT_RDWR);
        ::close(socket_fd);
      }

      throw;
    }

    /*
    // Init diameter session
    auto exchange_packet = generate_exchange_packet_();
    send_packet_(socket_fd, exchange_packet, 0);
    std::cout << "DDDD: to read after exchange" << std::endl;
    Diameter::Packet response = read_packet_(socket_fd, 0);
    std::cout << "DDDD: from read after exchange" << std::endl;
    std::optional<uint32_t> result_code;
    for (int i = 0; i < response.numberOfAVPs(); ++i)
    {
      const Diameter::AVP& avp = response.avp(i);
      if (avp.header().avpCode() == 268) //< Result-Code
      {
        result_code = avp.data().toUnsigned32();
      }
    }

    if (!result_code.has_value())
    {
      socket_close_(socket_fd);
      throw DiameterError("Prime exchange failed, no Result-Code in response");
    }
    else if(*result_code != 2001)
    {
      socket_close_(socket_fd);
      std::ostringstream ostr;
      ostr << "Prime exchange failed, Result-Code: " << *result_code;
      throw DiameterError(ostr.str());
    }
    */

    init_fun_(*this);

    ConnectionHolder res;
    res.socket_fd = socket_fd;
    //res.session_id = origin_host_ + ";" + std::to_string(Gears::safe_rand()) + ";0;" +
    //  std::to_string(Gears::safe_rand());

    return res;
  }

  void
  SCTPConnection::fill_addr_(struct sockaddr_in& res, const Endpoint& endpoint)
  {
    struct hostent* server = ::gethostbyname(endpoint.host.c_str());
    if(server == NULL)
    {
      std::ostringstream ostr;
      ostr << "Can't resolve host: " << endpoint.host;
    }

    bzero((char*)&res, sizeof(res));
    res.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char*)&res.sin_addr.s_addr, server->h_length);
    res.sin_port = ::htons(endpoint.port);
  }

  SCTPStreamConnection::SCTPStreamConnection(SCTPConnectionPtr connection, unsigned int stream_index)
    : sctp_connection_(std::move(connection)),
      stream_index_(stream_index)
  {}

  void
  SCTPStreamConnection::close()
  {
    sctp_connection_->stream_close(stream_index_);
  }

  void
  SCTPStreamConnection::connect()
  {
    sctp_connection_->connect();
  }

  void
  SCTPStreamConnection::send_packet(const ByteArray& send_packet)
  {
    sctp_connection_->stream_send_packet(stream_index_, send_packet);
  }

  std::vector<unsigned char>
  SCTPStreamConnection::read_bytes(unsigned long size)
  {
    return sctp_connection_->stream_read_bytes(stream_index_, size);
  }
}
