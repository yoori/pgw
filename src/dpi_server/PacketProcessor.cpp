#include <iostream>

#include <ndpi/ndpi_config.h>

#include "NetworkUtils.hpp"
#include "PacketProcessor.hpp"

namespace dpi
{
  PacketProcessor::PacketProcessor()
  {
  }

  void PacketProcessor::process_packet(
    const ndpi_flow_info* flow,
    const pcap_pkthdr* header)
  {
    const u_int16_t proto = flow ?
      (flow->detected_protocol.proto.app_protocol ? flow->detected_protocol.proto.app_protocol :
        flow->detected_protocol.proto.master_protocol) :
      0;

    std::cout << "PROTO: " << proto << std::endl;
    if (proto == NDPI_PROTOCOL_TELEGRAM_VOIP)
    {
      std::cout << "ndpi_process_packet: flow = " << flow << ", proto = " << proto <<
        ipv4_address_to_string(flow->src_ip) << " => " <<
        ipv4_address_to_string(flow->dst_ip) <<
        std::endl;
      u_int32_t src_ip = flow->src_ip;
      u_int32_t dst_ip = flow->dst_ip;
    }
  }
}
