#pragma once

#include <memory>
#include <pcap.h>

#include "UserSessionPacketProcessor.hpp"

namespace dpi
{
  struct NetworkPacketProcessor
  {
    virtual bool process_packet(
      const struct pcap_pkthdr* header,
      const void* packet,
      UserSessionPacketProcessor::Direction direction,
      const NetInterfacePtr& send_interface) = 0;
  };

  using NetworkPacketProcessorPtr = std::shared_ptr<NetworkPacketProcessor>;
}
