#pragma once

#include <memory>

#include <gears/CompositeActiveObject.hpp>

#include "Logger.hpp"
#include "NetInterfaceProcessor.hpp"
#include "NDPIPacketProcessor.hpp"
#include "PacketProcessor.hpp"
#include "ShapingManager.hpp"
#include "Manager.hpp"

namespace dpi
{
  /*
   */
  class NetInterfaceBridgeNDPIProcessor: public Gears::CompositeActiveObject
  {
  public:
    NetInterfaceBridgeNDPIProcessor(
      std::shared_ptr<dpi::NDPIPacketProcessor> ndpi_packet_processor,
      PacketProcessorPtr packet_processor,
      NetInterfacePtr interface1,
      NetInterfacePtr interface2,
      ManagerPtr manager,
      unsigned int threads,
      const LoggerPtr& logger);

  private:
    LoggerPtr logger_;
    ShapingManagerPtr shaping_manager_;
    NetInterfaceProcessorPtr int1_to_int2_processor_;
    NetInterfaceProcessorPtr int2_to_int1_processor_;
    ManagerPtr manager_;
  };
}
