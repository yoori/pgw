#pragma once

#include <memory>
#include <pcap.h>

namespace dpi
{
  struct NetworkPacketProcessor
  {
    virtual bool process_packet(
      const struct pcap_pkthdr* header,
      const void* packet) = 0;
  };

  using NetworkPacketProcessorPtr = std::shared_ptr<NetworkPacketProcessor>;
}
