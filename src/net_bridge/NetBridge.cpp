#include <memory>

#include <gears/AppUtils.hpp>

#include <dpi/DPIRunner.hpp>
#include <dpi/NetInterface.hpp>
#include <http_server/HttpServer.hpp>

class NetBridge
{
public:
  NetBridge(const std::string& int1, const std::string& int2)
    : int1_(std::make_unique<dpi::NetInterface>(int1.c_str())),
      int2_(std::make_unique<dpi::NetInterface>(int2.c_str()))
  {
  }

  std::unique_ptr<dpi::NetInterface> int1_;
  std::unique_ptr<dpi::NetInterface> int2_;
};

int main(int argc, char **argv)
{
  // read config
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_int1;
  Gears::AppUtils::StringOption opt_int2;
  args.add(Gears::AppUtils::equal_name("int1"), opt_int1);
  args.add(Gears::AppUtils::equal_name("int2"), opt_int2);
  args.parse(argc - 1, argv + 1);

  if (opt_int1->empty() || opt_int2->empty())
  {
    std::cerr << "interface1 and interface2 should be defined" << std::endl;
    return 1;
  }


  return 0;
}
