#include <vector>
#include <memory>
#include <thread>
#include <atomic>

#include <gears/Time.hpp>
#include <gears/Rand.hpp>
#include <gears/StringManip.hpp>
#include <gears/AppUtils.hpp>

#include <radius_module/DiameterSession.hpp>

std::atomic<int> req_count(0);

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_server_hostname("localhost");
  Gears::AppUtils::StringOption opt_origin_host("localhost");
  Gears::AppUtils::StringOption opt_origin_realm("localhost");
  Gears::AppUtils::Option<unsigned int> opt_port(3869);
  args.add(Gears::AppUtils::equal_name("server") || Gears::AppUtils::short_name("s"), opt_server_hostname);
  args.add(Gears::AppUtils::equal_name("port") || Gears::AppUtils::short_name("p"), opt_port);
  args.add(Gears::AppUtils::equal_name("origin-host"), opt_origin_host);
  args.add(Gears::AppUtils::equal_name("origin-realm"), opt_origin_realm);
  args.parse(argc - 1, argv + 1);

  std::string server_hostname = *opt_server_hostname;
  unsigned int port = *opt_port;

  if((port > 65535) || (port < 2000))
  {
    std::cerr << "Please enter port number between 2000 - 65535" << std::endl;
    return 0;
  }       

  try
  {
    std::shared_ptr<DiameterSession> session = std::make_shared<DiameterSession>(
      *opt_server_hostname,
      *opt_port,
      *opt_origin_host,
      *opt_origin_realm
      );

    session->send_cc_init(
      "7995160073",
      1 // Service Id
      );
  }
  catch(const Gears::Exception& ex)
  {
    std::cerr << "ERROR: " << ex.what() << std::endl;
  }

  return 0;
}
