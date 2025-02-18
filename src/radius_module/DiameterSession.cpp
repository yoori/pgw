#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <iostream>

#include <gears/StringManip.hpp>
#include <gears/Rand.hpp>

#include "AVPUtils.hpp"

#include "DiameterSession.hpp"


DiameterSession::DiameterSession(
  std::string connect_host,
  int connect_port,
  std::string origin_host,
  std::string origin_realm)
  : connect_host_(std::move(connect_host)),
    connect_port_(connect_port),
    origin_host_(std::move(origin_host)),
    origin_realm_(std::move(origin_realm)),
    application_id_(16777238),
    request_i_(0),
    socket_fd_(0)
{
  char buf[40];
  size_t sz = Gears::StringManip::int_to_str(Gears::safe_rand(), buf, sizeof(buf));
  buf[sz] = 0;
  session_id_ = "session.";
  session_id_ += buf;
}

DiameterSession::~DiameterSession()
{
  socket_close_();
}

bool
DiameterSession::send_cc_init(
  const std::string& msisdn,
  unsigned long service_id)
{
  const ByteArray send_packet = generate_cc_init_(msisdn, service_id);

  for (int retry_i = 0; retry_i < RETRY_COUNT_; ++retry_i)
  {
    try
    {
      send_packet_(send_packet);
      Diameter::Packet response = read_packet_();
      std::optional<uint32_t> result_code;
      for (int i = 0; i < response.numberOfAVPs(); ++i)
      {
	const Diameter::AVP& avp = response.avp(i);
	if (avp.header().avpCode() == 268) //< Result-Code
	{
	  result_code = avp.data().toUnsigned32();
	}
      }

      return result_code.has_value() && *result_code == 2001;
    }
    catch(const std::exception& ex)
    {
      std::cout << "EX: " << ex.what() << std::endl;
      if (retry_i == RETRY_COUNT_ - 1)
      {
	throw ex;
      }
    }
  }

  return false;
}

Diameter::Packet
DiameterSession::read_packet_()
{
  std::vector<unsigned char> head_buf = read_bytes_(4);
  uint32_t head = htonl(*(const uint32_t*)head_buf.data());
  int packet_size = head & 0xFFFFFF;
  //std::cout << "readed = " << read_res << ", packet_size = " << packet_size << std::endl;

  std::vector<unsigned char> read_buf = read_bytes_(packet_size - 4);
  head_buf.insert(head_buf.end(), read_buf.begin(), read_buf.end());

  try
  {
    std::cout << "To parse packet, head_buf.size = " << head_buf.size() << std::endl;
    return Diameter::Packet(ByteArray(&head_buf[0], head_buf.size()));
  }
  catch (const std::invalid_argument& ex)
  {
    throw DiameterError(std::string("Can't parse response: ") + ex.what());
  }
}

void
DiameterSession::send_packet_(const ByteArray& send_packet)
{
  if (socket_fd_ <= 0)
  {
    socket_init_();
  }

  int res = ::write(socket_fd_, send_packet.data(), send_packet.size());
  if (res < send_packet.size())
  {
    throw NetworkError("");
  }
}

void
DiameterSession::socket_close_()
{
  if (socket_fd_ > 0)
  {
    ::close(socket_fd_);
    socket_fd_ = 0;
  }
}

std::vector<unsigned char>
DiameterSession::read_bytes_(unsigned long size) const
{
  std::vector<unsigned char> buf(size);
  int read_pos = 0;
  while(read_pos < size)
  {
    int read_res = ::read(socket_fd_, &buf[read_pos], size - read_pos);
    std::cout << "read result = " << read_res << std::endl;

    if (read_res < 0)
    {
      char error_buf[128];
      int e = errno;
      strerror_r(e, error_buf, sizeof(error_buf));
      std::ostringstream ostr;
      ostr << "Diameter head read error, errno = " << e << ", message = " << error_buf;
      throw NetworkError(ostr.str());
    }
    else if (read_res == 0)
    {
      if (errno != EINPROGRESS || errno != EAGAIN)
      {
	throw ConnectionClosedOnRead("Connection closed on read");
      }
    }

    read_pos += read_res;
  }

  return buf;
}

void
DiameterSession::socket_init_()
{
  int socket_fd = ::socket(AF_INET, SOCK_STREAM, 0); // IPPROTO_SCTP);

  if(socket_fd < 0)
  {
    throw NetworkError("Cannot open socket");
  }

  struct hostent* server = ::gethostbyname(connect_host_.c_str());

  if(server == NULL)
  {
    throw NetworkError("Host does not exist");
  }

  struct sockaddr_in server_addr;
  bzero((char*)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char*)&server_addr.sin_addr.s_addr, server->h_length);
  server_addr.sin_port = htons(connect_port_);

  /*
  long arg;
  if ((arg = ::fcntl(socket_fd, F_GETFL, NULL)) < 0)
  {
    throw NetworkError("Can't set non blocking");
  }
  arg |= O_NONBLOCK;
  if (::fcntl(socket_fd, F_SETFL, arg) < 0)
  {
    throw NetworkError("Can't set non blocking");
  }
  */

  //std::cout << "To connect" << std::endl;
  int checker = ::connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  //std::cout << "From connect: " << checker << std::endl;

  if(checker < 0)
  {
    if (errno == EINPROGRESS)
    {
      std::cout << "EINPROGRESS" << std::endl;
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
      strerror_r(e, error_buf, sizeof(error_buf));
      std::ostringstream ostr;
      ostr << "Cannot connect to " <<
	connect_host_ << ":" << connect_port_ <<
	": errno = " << e << ", message = " << error_buf;
      throw NetworkError(ostr.str());
    }
  }

  socket_fd_ = socket_fd;

  // Init diameter session
  auto exchange_packet = generate_exchange_packet_();
  send_packet_(exchange_packet);
  Diameter::Packet response = read_packet_();
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
    throw DiameterError("Prime exchange failed, no Result-Code in response");
  }
  else if(*result_code != 2001)
  {
    std::ostringstream ostr;
    ostr << "Prime exchange failed, Result-Code: " << *result_code;
    throw DiameterError(ostr.str());
  }
}

ByteArray
DiameterSession::generate_cc_init_(
  const std::string& msisdn,
  unsigned long service_id)
  const
{
  return generate_base_cc_packet_(msisdn, service_id)
    .addAVP(create_int32_avp(416, 1)) // CC-Request-Type
    .updateLength()
    .deploy();
}

ByteArray
DiameterSession::generate_cc_update_(
  const std::string& msisdn,
  unsigned long service_id)
  const
{
  return generate_base_cc_packet_(msisdn, service_id)
    .addAVP(create_int32_avp(416, 2)) // CC-Request-Type
    .updateLength()
    .deploy();
}

ByteArray
DiameterSession::generate_cc_terminate_(
  const std::string& msisdn,
  unsigned long service_id)
  const
{
  return generate_base_cc_packet_(msisdn, service_id)
    .addAVP(create_int32_avp(416, 3)) // CC-Request-Type
    .updateLength()
    .deploy();
}

Diameter::Packet DiameterSession::generate_base_cc_packet_(
  const std::string& msisdn,
  unsigned long service_id)
  const
{
  return Diameter::Packet()
    .setHeader(
      Diameter::Packet::Header()
        .setCommandFlags(
           Diameter::Packet::Header::Flags()
           .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
        )
        .setCommandCode(272)
        .setApplicationId(4)
        .setHBHIdentifier(0x7ddf9367)
        .setETEIdentifier(0xc15ecb12)
    )
    .addAVP(create_string_avp(263, session_id_)) // Session-Id
    .addAVP(create_uint32_avp(258, application_id_)) // Auth-Application-Id
    .addAVP(create_string_avp(264, origin_host_)) // Origin-Host
    .addAVP(create_string_avp(296, origin_realm_)) // Origin-Realm
    .addAVP(create_string_avp(283, origin_realm_)) // Destination-Realm
    .addAVP(create_uint32_avp(415, ++request_i_)) // CC-Request-Number
    .addAVP(create_string_avp(30, "internet.sberbank-tele.com")) // Called-Station-Id
    //.addAVP(create_int32_avp(501, 3115221813)) // Access-Network-Charging-Address - CHECK TYPE
    //.addAVP(create_int32_avp(8, 177503142)) // Access-Network-Charging-Address - CHECK TYPE
    .addAVP(create_int32_avp(1009, 1)) // Online
    .addAVP(create_int32_avp(1008, 1)) // Offline
    .addAVP(create_avp( // Access-Network-Charging-Identifier-Gx
       1022,
       Diameter::AVP::Data()
         .addAVP(create_string_avp(503, "\x04")) // Access-Network-Charging-Identifier-Value - TO FIX
         ))
    //.addAVP(create_uint32_avp(278, 3801248757)) // Origin-State-Id
    .addAVP(create_int32_avp(6, 177503142)) // 3GPP-SGSN-Address: FILL IP
    .addAVP(create_int32_avp(1050, 177503142)) // AN-GW-Address=3GPP-SGSN-Address
    .addAVP(create_int32_avp(1032, 1004)) // RAT-Type
    .addAVP(create_int32_avp(1024, 1)) // Network-Request-Support
    .addAVP(create_int32_avp(18, 25020)) // 3GPP-SGSN-MCC-MNC
    /* TODO
    .addAVP(create_avp( // 3GPP-User-Location-Info
       22,
       Diameter::AVP::Data()
         .addAVP()
       )
    */
    .addAVP(create_avp( // Subscription-Id
       443,
       Diameter::AVP::Data()
         .addAVP(create_int32_avp(450, 0)) // Subscription-Id-Type = END_USER_E164
         .addAVP(create_string_avp(444, msisdn)) // Subscription-Id-Data
         ))
    .addAVP(create_int32_avp(1027, 5)) // IP-CAN-Type
    ;
}

ByteArray DiameterSession::generate_exchange_packet_() const
{
  static const uint8_t ADDR[] = { 0, 0x1, 0x0a, 0xee, 0x0c, 0xc4 };
  return Diameter::Packet()
    .setHeader(
      Diameter::Packet::Header()
        // Setting that it's request 
        .setCommandFlags(
           Diameter::Packet::Header::Flags()
           .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
        )
        .setCommandCode(257)
        .setApplicationId(0)
        .setHBHIdentifier(0x00000ad1)
        .setETEIdentifier(0x00000ad1)
    )
    .addAVP(create_string_avp(264, origin_host_)) // Origin-Host
    .addAVP(create_string_avp(296, origin_realm_)) // Origin-Realm
    .addAVP(create_octets_avp(257, ByteArray(ADDR, sizeof(ADDR)))) // Host-IP-Address
    .addAVP(create_uint32_avp(266, 2011)) // Vendor-Id
    .addAVP(create_string_avp(269, "3GPP Gx")) // Product-Name
    .addAVP(create_uint32_avp(299, 0)) // Inband-Security-Id
    .addAVP(create_uint32_avp(258, application_id_)) // Auth-Application-Id

    .updateLength()
    .deploy()
    ;
}
