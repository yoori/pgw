#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <pcap.h>

#include <gears/Exception.hpp>
#include <gears/ActiveObject.hpp>

namespace dpi
{
  class NetInterfaceProcessor: public Gears::SimpleActiveObject
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

  public:
    NetInterfaceProcessor(
      const char* interface_name,
      unsigned int threads = 1,
      unsigned int snaplen = 1536);

    virtual ~NetInterfaceProcessor();

    void send(const void* packet_buf, int packet_buf_size);

    const std::string& interface_name() const;

    bool live_capture() const;

    pcap_t* pcap_handle() const;

  protected:
    struct ProcessingContext
    {
      NetInterfaceProcessor* interface_processor;
      unsigned int thread_i;
    };

  protected:
    virtual void activate_object_();

    virtual void deactivate_object_();

    virtual void wait_object_();

    virtual void process_packet(
      unsigned int thread_i,
      const struct pcap_pkthdr* header,
      const u_char* packet);

    void processing_thread(unsigned int thread_i);

    static void ndpi_process_packet_(
      u_char* args,
      const struct pcap_pkthdr* header,
      const u_char* packet);

  private:
    const std::string interface_name_;
    const int num_threads_;
    const int PACKET_PROCESS_DELAY_MS_ = 1;
    const std::string bpf_filter_;
    struct bpf_program bpf_code_;
    struct bpf_program* bpf_cfilter_ = NULL;
    bool live_capture_ = false;
    pcap_t* pcap_handle_ = nullptr;

    std::mutex lock_;
    std::vector<std::unique_ptr<std::thread>> threads_;
  };

  using NetInterfaceProcessorPtr = std::shared_ptr<NetInterfaceProcessor>;
}

namespace dpi
{
  inline const std::string&
  NetInterfaceProcessor::interface_name() const
  {
    return interface_name_;
  }
}
