#pragma once

#include <memory>

#include <gears/CompositeActiveObject.hpp>

#include "NetInterfaceProcessor.hpp"
#include "NDPIPacketProcessor.hpp"

namespace dpi
{
  /*
   */
  class NetInterfaceBridgeNDPIProcessor: public Gears::CompositeActiveObject
  {
  public:
    NetInterfaceBridgeNDPIProcessor(
      std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor,
      NetInterfacePtr interface1,
      NetInterfacePtr interface2,
      unsigned int threads = 1);

  private:
    NetInterfaceProcessorPtr int1_to_int2_processor_;
    NetInterfaceProcessorPtr int2_to_int1_processor_;
  };
}
