#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>

#include <iostream>

#include <gears/AppUtils.hpp>

#include <dpi/PccConfig.hpp>

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_host;
  Gears::AppUtils::Option<unsigned int> opt_port;

  args.add(Gears::AppUtils::equal_name("host"), opt_host);
  args.add(Gears::AppUtils::equal_name("port"), opt_port);

  args.parse(argc - 1, argv + 1);

  struct sockaddr_in server_addr;
  int sockfd;

  if ((sockfd = ::socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    return 1;
  }

  ::memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = ::htons(*opt_port);
  server_addr.sin_addr.s_addr = INADDR_ANY; 

  RadProto::Packet send_packet;

  ::sendto(
    sockfd,
    (const char*)hello,
    strlen(hello),
    MSG_CONFIRM,
    (const struct sockaddr*)&server_addr,
    sizeof(server_addr));

  int n = ::recvfrom(
    sockfd,
    (char*)buffer,
    MAXLINE,  
    MSG_WAITALL, (struct sockaddr*)&servaddr, 
    &len);

  return 0;
}
