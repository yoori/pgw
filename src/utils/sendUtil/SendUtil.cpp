#include <string.h>
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <strings.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include <vector>
#include <memory>
#include <thread>
#include <atomic>

#include <gears/Time.hpp>
#include <gears/Rand.hpp>
#include <gears/StringManip.hpp>
#include <gears/AppUtils.hpp>
#include <Diameter/Packet.hpp>

std::atomic<int> req_count(0);

Diameter::AVP
create_avp(unsigned int avp_code, Diameter::AVP::Data data)
{
  return Diameter::AVP()
    .setHeader(
      Diameter::AVP::Header()
        .setAVPCode(avp_code)
        .setFlags(
          Diameter::AVP::Header::Flags()
            .setFlag(Diameter::AVP::Header::Flags::Bits::Mandatory, true)
          )
        )
        .setData(data)
        // Updating AVP length field, according to header and data value.
        .updateLength();
}

Diameter::AVP
create_string_avp(unsigned int avp_code, const std::string& value)
{
  return create_avp(avp_code, Diameter::AVP::Data().setOctetString(ByteArray::fromASCII(value.c_str())));
}

Diameter::AVP
create_octets_avp(unsigned int avp_code, const ByteArray& value)
{
  return create_avp(avp_code, Diameter::AVP::Data().setOctetString(value));
}

Diameter::AVP
create_uint32_avp(unsigned int avp_code, uint32_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setUnsigned32(val));
}

Diameter::AVP
create_uint64_avp(unsigned int avp_code, uint64_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setUnsigned64(val));
}

Diameter::AVP
create_int32_avp(unsigned int avp_code, int32_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setInteger32(val));
}

Diameter::AVP
create_int64_avp(unsigned int avp_code, int64_t val)
{
  return create_avp(avp_code, Diameter::AVP::Data().setInteger64(val));
}

Diameter::Packet
generate_bbase_packet(
  const std::string& origin_host,
  const std::string& origin_realm,
  const std::string& session_id,
  const std::string& msisdn,
  unsigned long service_id)
{
  return Diameter::Packet()
    .setHeader(
      Diameter::Packet::Header()
        // Setting that it's request 
        .setCommandFlags(
           Diameter::Packet::Header::Flags()
           .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
        )
        .setCommandCode(272)
        .setApplicationId(4)
        .setHBHIdentifier(0x7ddf9367)
        .setETEIdentifier(0xc15ecb12)
    )
    .addAVP(create_string_avp(263, session_id)) // Session-Id
    .addAVP(create_uint32_avp(258, 16777238)) // Auth-Application-Id
    .addAVP(create_string_avp(264, origin_host)) // Origin-Host
    .addAVP(create_string_avp(296, origin_realm)) // Origin-Realm
    .addAVP(create_string_avp(283, origin_realm)) // Destination-Realm
    .addAVP(create_string_avp(30, "internet.sberbank-tele.com")) // Called-Station-Id
    .addAVP(create_int32_avp(501, 3115221813)) // Access-Network-Charging-Address - CHECK TYPE
    .addAVP(create_int32_avp(8, 177503142)) // Access-Network-Charging-Address - CHECK TYPE
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

Diameter::Packet
generate_base_packet(
  const std::string& origin_host,
  const std::string& origin_realm,
  const std::string& session_id,
  const std::string& msisdn,
  unsigned long service_id)
{
  return generate_bbase_packet(origin_host, origin_realm, session_id, msisdn, service_id)
    .addAVP(create_avp( // User-Equipment-Info
       458,
       Diameter::AVP::Data()
         .addAVP(create_int32_avp(459, 0)) // User-Equipment-Info-Type
         .addAVP(create_string_avp(460, msisdn)) // User-Equipment-Info-Value
         ))
    /*
    .addAVP(create_avp(
      456,
      Diameter::AVP::Data()
        .addAVP(create_avp(
          437,
          Diameter::AVP::Data() // empty
          )) // Requested-Service-Unit
        .addAVP(create_uint32_avp(432, service_id)) // Rating-Group
        .addAVP(create_uint32_avp(439, service_id)) // Service-Identifier
      ))
    */
    ;
}

ByteArray
generate_exchange_packet(const std::string& origin_host, const std::string& origin_realm)
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
    .addAVP(create_string_avp(264, origin_host)) // Origin-Host
    .addAVP(create_string_avp(296, origin_realm)) // Origin-Realm

    .addAVP(create_octets_avp(257, ByteArray(ADDR, sizeof(ADDR)))) // Host-IP-Address
    //.addAVP(create_uint32_avp(266, 2011)) // Vendor-Id
    .addAVP(create_string_avp(269, "3GPP Gx")) // Product-Name
    .addAVP(create_uint32_avp(299, 0)) // Inband-Security-Id
    .addAVP(create_uint32_avp(258, 16777238)) // Auth-Application-Id

    .updateLength()
    .deploy()
    ;
}

class DiameterSession
{
public:
  DiameterSession(std::string origin_host, std::string origin_realm)
    : origin_host_(std::move(origin_host)),
      origin_realm_(std::move(origin_realm)),
      service_id_(65108),
      msisdn_("89263411124"),
      request_i_(0)
  {
    char buf[40];
    size_t sz = Gears::StringManip::int_to_str(Gears::safe_rand(), buf, sizeof(buf));
    buf[sz] = 0;
    session_id_ = "session.";
    session_id_ += buf;
  }

  std::vector<ByteArray>
  init()
  {
    return std::vector<ByteArray>({
      generate_exchange_packet(origin_host_, origin_realm_),
      generate_base_packet(origin_host_, origin_realm_, session_id_, msisdn_, service_id_)
        //.addAVP(create_string_avp(263, session_id_)) // Session-Id
        .addAVP(create_int32_avp(416, 1)) // CC-Request-Type
        .addAVP(create_uint32_avp(415, ++request_i_)) // CC-Request-Number
        // Updating Message length field, accordign to added AVPs
        .updateLength()
        // Serializing Packet to ByteArray.
        .deploy()
      });
  }

  ByteArray
  update()
  {
    return generate_base_packet(origin_host_, origin_realm_, session_id_, msisdn_, service_id_)
      //.addAVP(create_string_avp(263, session_id_)) // Session-Id
      .addAVP(create_int32_avp(416, 2)) // CC-Request-Type
      .addAVP(create_uint32_avp(415, ++request_i_)) // CC-Request-Number
      // Updating Message length field, accordign to added AVPs
      .updateLength()
      // Serializing Packet to ByteArray.
      .deploy();
  }

  ByteArray
  terminate()
  {
    return generate_bbase_packet(origin_host_, origin_realm_, session_id_, msisdn_, service_id_)
      //.addAVP(create_string_avp(263, session_id_)) // Session-Id
      .addAVP(create_int32_avp(416, 3)) // CC-Request-Type
      .addAVP(create_uint32_avp(415, ++request_i_)) // CC-Request-Number
      // Updating Message length field, accordign to added AVPs
      .updateLength()
      // Serializing Packet to ByteArray.
      .deploy();
  }

private:
  std::string origin_host_;
  std::string origin_realm_;
  std::string session_id_;
  unsigned int service_id_;
  std::string msisdn_;
  unsigned long request_i_;
};

void
diameter_read_thread(int socket_fd)
{
  char data[1024];
  ssize_t data_read;
  while((data_read = ::recv(socket_fd, data, sizeof(data), 0)) > 0)
  {
    std::cout << "Received " << data_read << " bytes" << std::endl;
  }

  if(data_read == -1)
  {
    std::cerr << "Cannot read, error" << std::endl;
  }
}

void
print_stats()
{
  while(true)
  {
    Gears::Time now = Gears::Time::get_time_of_day();
    std::cout << "[" << now.gm_ft() << "]: sent requests: " << req_count.load() << std::endl;
    ::sleep(1);
  }

  std::cout << "finish stats thread" << std::endl;
}

void
send_init(
  std::string server_hostname,
  unsigned int port,
  const std::string& origin_host,
  const std::string& origin_realm)
{
  // create client skt
  int socket_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

  if(socket_fd < 0)
  {
    std::cerr << "Cannot open socket" << std::endl;
    return;
  }

  /*
  if(::fcntl(socket_fd, F_SETFL, ::fcntl(socket_fd, F_GETFL) | O_NONBLOCK) < 0)
  {
    std::cerr << "Can't set non-blocking" << std::endl;
    return;
  }
  */

  struct hostent* server = ::gethostbyname(server_hostname.c_str());

  if(server == NULL)
  {
    std::cerr << "Host does not exist" << std::endl;
    return;
  }

  struct sockaddr_in server_addr;
  bzero((char*)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;

  bcopy((char *)server->h_addr, (char*)&server_addr.sin_addr.s_addr, server->h_length);
  server_addr.sin_port = htons(port);

  int checker = ::connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

  if(checker < 0)
  {
    char error_buf[128];
    int e = errno;
    strerror_r(e, error_buf, sizeof(error_buf));
    std::cerr << "Cannot connect to " << server_hostname << ":" << port <<
      ": errno = " << e << ", message = " << error_buf <<
      std::endl;
    return;
  }

  char buf[40];
  size_t sz = Gears::StringManip::int_to_str(Gears::safe_rand(), buf, sizeof(buf));
  buf[sz] = 0;

  //std::string origin_host = std::string("lggg") + buf + ".gloworld.com";
  std::shared_ptr<std::thread> read_thread(new std::thread(diameter_read_thread, socket_fd));

  // send stuff to server
  std::unique_ptr<DiameterSession> session(new DiameterSession(origin_host, origin_realm));

  std::vector<ByteArray> packets = session->init();
  std::vector<unsigned char> ubuf;

  for(auto packet_it = packets.begin(); packet_it != packets.end(); ++packet_it)
  {
    auto old_size = ubuf.size();
    ubuf.resize(old_size + packet_it->size());
    ::memcpy(ubuf.data() + old_size, packet_it->data(), packet_it->size());

    //::write(socket_fd, packet_it->data(), packet_it->size());
  }

  ::write(socket_fd, ubuf.data(), ubuf.size());

  /*
  for(int i = 0; i < 1000; ++i)
  {
    ByteArray upd_packet = session->update();
    int res = ::write(socket_fd, upd_packet.data(), upd_packet.size());
    std::cout << "Sent " << res << " bytes" << std::endl;
    usleep(10 * 1000);
  }
  */

  ::sleep(1);
  ::close(socket_fd);

  read_thread->join();
}

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_server_hostname("localhost");
  Gears::AppUtils::StringOption opt_origin_host("localhost");
  Gears::AppUtils::StringOption opt_origin_realm("localhost");
  Gears::AppUtils::Option<unsigned int> opt_port(3869);
  args.add(Gears::AppUtils::equal_name("server") || Gears::AppUtils::short_name("s"), opt_server_hostname);
  args.add(Gears::AppUtils::equal_name("origin-host"), opt_origin_host);
  args.add(Gears::AppUtils::equal_name("origin-realm"), opt_origin_realm);
  args.add(Gears::AppUtils::equal_name("port") || Gears::AppUtils::short_name("p"), opt_port);
  args.parse(argc - 1, argv + 1);

  std::string server_hostname = *opt_server_hostname;
  unsigned int port = *opt_port;

  if((port > 65535) || (port < 2000))
  {
    std::cerr << "Please enter port number between 2000 - 65535" << std::endl;
    return 0;
  }       

  send_init(server_hostname, port, *opt_origin_host, *opt_origin_realm);

  return 0;
}
