#include <boost/asio.hpp>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <cstdint>

#include <gears/AppUtils.hpp>

#include "server.h"
#include "error.h"

using boost::system::error_code;

namespace
{
  void print_help(const std::string& programName)
  {
    std::cout << "Usage: " << programName <<
      " -s/--secret <secret> [-p/--port <port>] [-h/--help] [-v/--version]\n" <<
      "\t --secret, -s <secret> - shared secret for password encryption by client and server;\n" <<
      "\t --port, -p <port>     - port number for the socket;\n" <<
      "\t --help, -h            - print this help;\n" <<
      "\t --version, -v         - print version.\n";
  }
}

int main(int argc, char* argv[])
{
  Gears::AppUtils::StringOption opt_secret;
  Gears::AppUtils::Option<unsigned int> opt_port(1812);
  Gears::AppUtils::Args args;
  args.add(Gears::AppUtils::equal_name("secret"), opt_secret);
  args.add(Gears::AppUtils::equal_name("port"), opt_port);
  args.parse(argc - 1, argv + 1);

  if (opt_secret->empty())
  {
    std::cerr << "Needs a parameter secret - shared secret for password encryption by client and server.\n";
    return 1;
  }

  try
  {
    boost::asio::io_service io_service;
    Server server(io_service, *opt_secret, *opt_port, "/usr/share/freeradius/dictionary");
    io_service.run();
  }
  catch (const std::exception& e)
  {
    std::cerr << "Exception: " << e.what() <<"\n";
  }

  return 0;
}
