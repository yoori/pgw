#include <memory>

#include <gears/AppUtils.hpp>

#include <dpi/NetInterfaceProcessor.hpp>
#include <http_server/HttpServer.hpp>

class NetBridgeProcessor: public dpi::NetInterfaceProcessor
{
public:
  NetBridgeProcessor(dpi::NetInterfacePtr interface, unsigned int threads = 1)
    : dpi::NetInterfaceProcessor(interface, threads)
  {}

  void set_send_interface(dpi::NetInterfacePtr send_int)
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
  dpi::NetInterfacePtr send_int_;
};

class NetBridge: public Gears::CompositeActiveObject
{
public:
  NetBridge(dpi::NetInterfacePtr int1, dpi::NetInterfacePtr int2)
    : int1_processor_(std::make_unique<NetBridgeProcessor>(int1)),
      int2_processor_(std::make_unique<NetBridgeProcessor>(int2))
  {
    int1_processor_->set_send_interface(int2);
    int2_processor_->set_send_interface(int1);

    add_child_object(int1_processor_);
    add_child_object(int2_processor_);
  }

  virtual ~NetBridge()
  {
  }

private:
  std::shared_ptr<dpi::NetInterface> int1_;
  std::shared_ptr<dpi::NetInterface> int2_;
  std::shared_ptr<NetBridgeProcessor> int1_processor_;
  std::shared_ptr<NetBridgeProcessor> int2_processor_;
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

  auto int1 = std::make_shared<dpi::NetInterface>(opt_int1->c_str());
  auto int2 = std::make_shared<dpi::NetInterface>(opt_int2->c_str());
  auto net_bridge = std::make_shared<NetBridge>(int1, int2);
  net_bridge->activate_object();
  net_bridge->wait_object();

  return 0;
}
