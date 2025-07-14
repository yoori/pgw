#pragma once

#include <memory>
#include <string>
#include <thread>
#include <mutex>

#include <gears/Exception.hpp>
#include <gears/ActiveObject.hpp>

#include "PacketProcessor.hpp"
#include "NetworkPacketProcessor.hpp"
#include "ReaderUtil.hpp"
#include "DPIPrintUtils.hpp"
#include "UserSessionPacketProcessor.hpp"
#include "FlowTraits.hpp"
#include "Config.hpp"
#include "ProtocolAdapter.hpp"

namespace dpi
{
  class NDPIPacketProcessor
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    NDPIPacketProcessor(
      const Config& config,
      int datalink_type
      );

    virtual ~NDPIPacketProcessor() noexcept;

    FlowTraits process_packet(
      const struct pcap_pkthdr* header,
      const void* packet);

    void set_datalink_type(int datalink_type);

  private:
    struct NDPIThreadContext
    {
      NDPIPacketProcessor* ndpi_packet_processor;
      unsigned int thread_id;
    };

  private:
    FlowTraits ndpi_process_packet_(
      unsigned int thread_id,
      const struct pcap_pkthdr* header,
      const void* packet);

    void init_();

    void init_ndpi_();

    void clear_ndpi_();

    void clear_();

    void setup_detection_(
      DPIHandleHolder::Info& dpi_handle_info,
      u_int16_t thread_id,
      struct ndpi_global_context* g_ctx);

    void terminate_detection_(
      DPIHandleHolder::Info& dpi_handle_info,
      u_int16_t thread_id);

    void clear_idle_flows_(unsigned int thread_id);

    static void node_proto_guess_walker_(
      const void* node,
      ndpi_VISIT which,
      int depth,
      void* user_data);

    static void node_idle_scan_walker_(
      const void *node, ndpi_VISIT which, int depth, void *user_data);

  private:
    const ProtocolAdapter protocol_adapter_;
    const Config config_;
    const PacketProcessorPtr packet_processor_;
    int datalink_type_;
    DPIHandleHolder dpi_handle_holder_;
    struct ndpi_global_context* g_ctx_;
    std::mutex ndpi_lock_;
  };

  using NDPIPacketProcessorPtr = std::shared_ptr<NDPIPacketProcessor>;
}
