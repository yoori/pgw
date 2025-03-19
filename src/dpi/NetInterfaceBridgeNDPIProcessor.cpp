#include "UserSessionPacketProcessor.hpp"
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
      unsigned int threads = 1,
      UserSessionPacketProcessor::Direction direction =
        UserSessionPacketProcessor::Direction::D_NONE
      )
      : dpi::NetInterfaceProcessor(std::move(interface), threads),
        ndpi_packet_processor_(std::move(ndpi_packet_processor)),
        send_interface_(std::move(send_interface)),
        direction_(direction)
    {}

    virtual void process_packet(
      unsigned int /*thread_i*/,
      const struct pcap_pkthdr* header,
      const u_char* packet)
    {
      if (ndpi_packet_processor_->process_packet(header, packet, direction_))
      {
        try
        {
          send_interface_->send(packet, header->caplen);
        }
        catch(const Gears::Exception&)
        {}
      }
      /*
      else
      {
        std::cout << "BLOCK PACKET" << std::endl;
      }
      */
    }

  private:
    std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor_;
    NetInterfacePtr send_interface_;
    const UserSessionPacketProcessor::Direction direction_;
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
          ndpi_packet_processor,
          interface1,
          interface2,
          threads,
          UserSessionPacketProcessor::Direction::D_OUTPUT
        )),
      // interface2 => interface1 direction
      int2_to_int1_processor_(
        std::make_shared<NetInterfaceBridgeProcessor>(
          ndpi_packet_processor,
          interface2,
          interface1,
          threads,
          UserSessionPacketProcessor::Direction::D_INPUT
        ))
  {
    add_child_object(int1_to_int2_processor_);
    add_child_object(int2_to_int1_processor_);
  }
}
