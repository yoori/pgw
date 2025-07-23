#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>

#include <iostream>

#include "radproto/attribute_types.h"
#include "packet.h"

#include <gears/AppUtils.hpp>

#include <dpi/PccConfig.hpp>
#include <dpi/RadiusConnection.hpp>

using namespace dpi;

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_host;
  Gears::AppUtils::Option<unsigned int> opt_port;
  Gears::AppUtils::StringOption opt_secret("sbtel");

  Gears::AppUtils::StringOption opt_session_id("b9ae8335020cbf5c");
  Gears::AppUtils::StringOption opt_msisdn("79662660021");

  args.add(Gears::AppUtils::equal_name("host"), opt_host);
  args.add(Gears::AppUtils::equal_name("port"), opt_port);
  args.add(Gears::AppUtils::equal_name("secret"), opt_secret);

  args.add(Gears::AppUtils::equal_name("session-id"), opt_session_id);
  args.add(Gears::AppUtils::equal_name("msisdn"), opt_msisdn);

  args.parse(argc - 1, argv + 1);

  std::unique_ptr<RadiusConnection> radius_connection = std::make_unique<RadiusConnection>(
    *opt_host,
    *opt_port,
    *opt_secret);
  radius_connection->activate_object();

  RadiusConnection::DisconnectRequest request;
  request.session_id = "b9ae8335020cbf5c";
  request.msisdn = "79662660021";
  request.framed_ip_address = 0x0AF34001;

  radius_connection->send_disconnect(request);

  sleep(1); // wait response

  radius_connection->deactivate_object();
  radius_connection->wait_object();

  return 0;
}
