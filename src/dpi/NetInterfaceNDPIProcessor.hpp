#pragma once

#include "NetInterfaceProcessor.hpp"
#include "NDPIPacketProcessor.hpp"

namespace dpi
{
  class NetInterfaceNDPIProcessor: public dpi::NetInterfaceProcessor
  {
  public:
    NetInterfaceNDPIProcessor(
      std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor,
      NetInterfacePtr interface,
      unsigned int threads = 1)
      : dpi::NetInterfaceProcessor(std::move(interface), threads),
        ndpi_packet_processor_(std::move(ndpi_packet_processor))
    {}

    virtual void process_packet(
      unsigned int /*thread_id*/,
      const struct pcap_pkthdr* header,
      const u_char* packet)
      override
    {
      bool send_packet = ndpi_packet_processor_->process_packet(header, packet);
    }

  private:
    std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor_;
  };
}
