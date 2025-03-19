#include "NetInterfaceBridgeNDPIProcessor.hpp"

namespace dpi
{
  class NetInterfaceBridgeProcessor: public dpi::NetInterfaceProcessor
  {
  public:
    NetInterfaceBridgeProcessor(
      std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor,
      NetInterfacePtr interface,
      NetInterfacePtr send_interface,
      unsigned int threads = 1
      )
      : dpi::NetInterfaceProcessor(std::move(interface), threads),
        ndpi_packet_processor_(std::move(ndpi_packet_processor)),
        send_interface_(std::move(send_interface))
    {}

    virtual void process_packet(
      unsigned int /*thread_i*/,
      const struct pcap_pkthdr* header,
      const u_char* packet)
    {
      if (ndpi_packet_processor_->process_packet(header, packet))
      {
        try
        {
          send_interface_->send(packet, header->caplen);
        }
        catch(const Gears::Exception&)
        {}
      }
    }

  private:
    std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor_;
    NetInterfacePtr send_interface_;
  };

  NetInterfaceBridgeNDPIProcessor::NetInterfaceBridgeNDPIProcessor(
    std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor,
    NetInterfacePtr interface1,
    NetInterfacePtr interface2,
    unsigned int threads)
    :
      // interface1 => interface2 direction
      int1_to_int2_processor_(
        std::make_shared<NetInterfaceBridgeProcessor>(
          ndpi_packet_processor, interface1, interface2, threads)),
      // interface2 => interface1 direction
      int2_to_int1_processor_(
        std::make_shared<NetInterfaceBridgeProcessor>(
          ndpi_packet_processor, interface2, interface1, threads))
  {
    add_child_object(int1_to_int2_processor_);
    add_child_object(int2_to_int1_processor_);
  }
}
