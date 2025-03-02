#pragma once

#include <memory>

#include <pcap.h>

#include "ReaderUtil.hpp"

namespace dpi
{
  class PacketProcessor
  {
  public:
    PacketProcessor();

    void process_packet(
      const ndpi_flow_info* flow,
      const pcap_pkthdr* header);

  private:

  };

  using PacketProcessorPtr = std::shared_ptr<PacketProcessor>;
}
