#include <iostream>
#include <sstream>

#include <gears/Time.hpp>

#include <ndpi/ndpi_config.h>
#include <ndpi_api.h>

#include "NetworkUtils.hpp"
#include "PacketProcessor.hpp"

namespace dpi
{
  uint32_t adapt_ip(
    unsigned char ip1,
    unsigned char ip2,
    unsigned char ip3,
    unsigned char ip4)
  {
    return ip1 | (ip2 << 8) | (ip3 << 16) | (ip4 << 24);
  }
  
  PacketProcessor::PacketProcessor()
  {
    sber_ips_.emplace(adapt_ip(194, 54, 14, 131)); // online.sberbank.ru
    sber_ips_.emplace(adapt_ip(95, 181, 181, 241)); // app.sberbank.ru
  }

  void PacketProcessor::process_packet(
    struct ndpi_workflow* workflow,
    const ndpi_flow_info* flow,
    const pcap_pkthdr* header)
  {
    /*
    if (flow)
    {
      const struct ndpi_flow_struct* ndpi_flow = flow->ndpi_flow;
      if (ndpi_flow)
      {
        std::cout << "============" << std::endl;
        for (int i = 0; i < NDPI_PROTOCOL_SIZE; ++i)
        {
          std::cout << "PROTO #" << i << ": " << flow->ndpi_flow->detected_protocol_stack[i] << std::endl;
        }
        std::cout << "============" << std::endl;
      }
    }
    */

    //std::cout << "PROCESS PACKET #" << packet_i_ << std::endl;
    ++packet_i_;

    //const u_int16_t app_protocol = flow ? flow->detected_protocol.proto.app_protocol : 0;
    const u_int16_t proto = flow ?
      (flow->detected_protocol.proto.app_protocol ? flow->detected_protocol.proto.app_protocol :
        flow->detected_protocol.proto.master_protocol) :
      0;

    /*
    const char* protocol_name = ndpi_get_proto_name(
      workflow->ndpi_struct,
      ndpi_map_ndpi_id_to_user_proto_id(workflow->ndpi_struct, proto)
    );

    std::cout << "PACKET: app_protocol = " << app_protocol << ", proto = " << proto << "(" <<
      protocol_name << ")" << ", monitoring_enabled = " << monitoring_enabled << std::endl;
    */

    if (flow)
    {
      process_packet_(proto, flow->src_ip, flow->dst_ip);
    }
  }

  void PacketProcessor::process_packet_(
    u_int16_t proto,
    uint32_t src_ip,
    uint32_t dst_ip
    )
  {
    if (proto == NDPI_PROTOCOL_TELEGRAM_VOIP)
    {
      process_telegram_call_packet_(src_ip, dst_ip);
    }
    else if (sber_ips_.find(dst_ip) != sber_ips_.end() ||
      sber_ips_.find(src_ip) != sber_ips_.end())
    {
      process_sber_packet_(src_ip, dst_ip);
      /*
      std::cout << "sber connect: " <<
        ipv4_address_to_string(src_ip) << " => " <<
        ipv4_address_to_string(dst_ip) <<
        std::endl;
      */
      const std::lock_guard<std::mutex> lock(client_states_lock_);
      ClientState& client_state = client_states_[src_ip];
    }
  }

  void PacketProcessor::process_sber_packet_(
    uint32_t src_ip,
    uint32_t dst_ip
    )
  {
    const auto now = Gears::Time::get_time_of_day();

    bool sber_opening_started = false;
    bool sber_on_call_opening = false;

    {
      const std::lock_guard<std::mutex> lock(client_states_lock_);

      ClientState& client_state = client_states_[src_ip];

      //std::cout << "client_state.sber_packet_last_timestamp = " << client_state.sber_packet_last_timestamp.gm_ft() << std::endl;
      if (client_state.sber_packet_last_timestamp + SBER_OPEN_MAX_PERIOD_ < now)
      {
        sber_opening_started = true;
      }

      client_state.sber_packet_last_timestamp = now;

      if (client_state.telegram_call_packet_last_timestamp + TELEGRAM_CALL_MAX_PERIOD_ < now)
      {
        // telegram call finished
        client_state.telegram_call_packet_last_timestamp = Gears::Time::ZERO;
      }

      if (client_state.telegram_call_packet_last_timestamp != Gears::Time::ZERO &&
        //< current telegram call is active
        client_state.telegram_call_packet_start_timestamp !=
          client_state.telegram_call_with_sber_open_start_timestamp
        // < no event generated for this call
        )
      {
        client_state.telegram_call_with_sber_open_start_timestamp =
          client_state.telegram_call_packet_start_timestamp;

        sber_on_call_opening = true;
      }
    }

    //std::cout << "sber_opening_started = " << sber_opening_started << std::endl;
    if (sber_opening_started)
    {
      log_event_("sber open", src_ip, dst_ip);
    }

    if (sber_on_call_opening)
    {
      log_event_("sber open on telegram call", src_ip, dst_ip);
    }
  }

  void PacketProcessor::process_telegram_call_packet_(
    uint32_t src_ip,
    uint32_t dst_ip
    )
  {
    const auto now = Gears::Time::get_time_of_day();
    bool call_started = false;

    {
      const std::lock_guard<std::mutex> lock(client_states_lock_);
      ClientState& client_state = client_states_[src_ip];
      if (client_state.telegram_call_packet_last_timestamp + TELEGRAM_CALL_MAX_PERIOD_ < now)
      {
        // previous call finished - start new call.
        client_state.telegram_call_packet_start_timestamp = now;
        call_started = true;
      }
      client_state.telegram_call_packet_last_timestamp = now;
    }

    if (call_started)
    {
      log_event_("telegram call", src_ip, dst_ip);
    }
  }

  bool PacketProcessor::telegram_call_in_progress_i_(const ClientState& client_state)
  {
    const auto now = Gears::Time::get_time_of_day();
    return client_state.telegram_call_packet_last_timestamp + Gears::Time(30) < now;
  }

  void PacketProcessor::log_event_(
    const std::string& event,
    uint32_t src_ip,
    uint32_t dst_ip
    )
  {
    std::ostringstream ostr;
    ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] EVENT '" << event << "': " <<
      ipv4_address_to_string(src_ip) << " => " <<
      ipv4_address_to_string(dst_ip) <<
      std::endl;
    std::cout << ostr.str() << std::flush;
  }
}
