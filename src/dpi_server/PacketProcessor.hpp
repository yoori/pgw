#pragma once

#include <memory>
#include <unordered_set>
#include <unordered_map>

#include <pcap.h>

#include <gears/Time.hpp>

#include "ReaderUtil.hpp"

namespace dpi
{
  class PacketProcessor
  {
  public:
    PacketProcessor();

    void process_packet(
      struct ndpi_workflow* workflow,
      const ndpi_flow_info* flow,
      const pcap_pkthdr* header);

  private:
    struct ClientState
    {
      Gears::Time telegram_call_packet_start_timestamp;
      Gears::Time telegram_call_packet_last_timestamp;

      Gears::Time telegram_call_with_sber_open_start_timestamp;

      Gears::Time sber_packet_last_timestamp;
    };

    void process_packet_(
      u_int16_t proto,
      uint32_t src_ip,
      uint32_t dst_ip);

    void process_telegram_call_packet_(
      uint32_t src_ip,
      uint32_t dst_ip);

    void process_sber_packet_(
      uint32_t src_ip,
      uint32_t dst_ip);

    static bool telegram_call_in_progress_i_(
      const ClientState& client_state);

    static void log_event_(
      const std::string& event,
      uint32_t src_ip,
      uint32_t dst_ip);
    
  private:
    const Gears::Time TELEGRAM_CALL_MAX_PERIOD_ = Gears::Time(30);
    const Gears::Time SBER_OPEN_MAX_PERIOD_ = Gears::Time(60);

    int packet_i_ = 0;
    std::unordered_set<uint32_t> sber_ips_;

    std::mutex client_states_lock_;
    std::unordered_map<uint32_t, ClientState> client_states_;
  };

  using PacketProcessorPtr = std::shared_ptr<PacketProcessor>;
}
