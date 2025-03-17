#include <memory>

#include <gears/AppUtils.hpp>

#include <dpi/DPIRunner.hpp>
#include <dpi/NetInterfaceProcessor.hpp>
#include <http_server/HttpServer.hpp>

class NetBridgeProcessor: public dpi::NetInterfaceProcessor
{
public:
  NetBridgeProcessor(const char* interface_name, unsigned int threads = 1)
    : dpi::NetInterfaceProcessor(interface_name, threads, 20000)
  {}

  void set_send_interface(std::shared_ptr<NetBridgeProcessor> send_int)
  {
    send_int_ = send_int;
  }

  virtual void process_packet(
    unsigned int /*thread_id*/,
    const struct pcap_pkthdr* header,
    const u_char* packet)
    override
  {
    if (send_int_)
    {
      try
      {
        send_int_->send(packet, header->len);
      }
      catch(const Gears::Exception& ex)
      {
        std::cerr << "Error on sending packet to " << send_int_->interface_name() << ": " <<
          ex.what() << std::endl;
      }
    }
  }

private:
  std::shared_ptr<NetBridgeProcessor> send_int_;
};

class NetBridge: public Gears::CompositeActiveObject
{
public:
  NetBridge(const std::string& int1, const std::string& int2)
    : int1_(std::make_unique<NetBridgeProcessor>(int1.c_str())),
      int2_(std::make_unique<NetBridgeProcessor>(int2.c_str()))
  {
    int1_->set_send_interface(int2_);
    int2_->set_send_interface(int1_);

    add_child_object(int1_);
    add_child_object(int2_);
  }

  virtual ~NetBridge()
  {
    int1_->set_send_interface(nullptr);
    int2_->set_send_interface(nullptr);
  }

private:
  std::shared_ptr<NetBridgeProcessor> int1_;
  std::shared_ptr<NetBridgeProcessor> int2_;
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

  auto net_bridge = std::make_shared<NetBridge>(opt_int1->c_str(), opt_int2->c_str());
  net_bridge->activate_object();
  net_bridge->wait_object();

  return 0;
}
