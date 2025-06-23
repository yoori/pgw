#pragma once

#include <iostream>
#include <Diameter/Packet.hpp>

namespace dpi
{
  class DiameterPacketDecoder
  {
  public:
    std::string
    packet_to_string(const Diameter::Packet& packet);

  private:
    std::string
    avp_to_string_(const Diameter::AVP& avp);

  private:
    
  };
}
