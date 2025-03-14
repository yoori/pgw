#pragma once

#include <string>
#include <pcap.h>

#include <gears/Exception.hpp>

namespace dpi
{
  class NetInterface
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

  public:
    NetInterface(const char* interface_name);

    bool live_capture() const;

  private:
    const int PACKET_PROCESS_DELAY_MS_ = 1;
    const std::string bpf_filter_;
    struct bpf_program bpf_code_;
    struct bpf_program* bpf_cfilter_ = NULL;
    bool live_capture_ = false;
    pcap_t* pcap_handle_ = nullptr;
  };
}
