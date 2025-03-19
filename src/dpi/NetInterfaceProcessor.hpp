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
  class NetInterface
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

  public:
    NetInterface(
      const char* interface_name,
      unsigned int snaplen = 1536);

    virtual ~NetInterface() noexcept;

    const std::string& interface_name() const;

    pcap_t* pcap_handle() const;

    void send(const void* packet_buf, int packet_buf_size);

    bool live_capture() const;

  private:
    const std::string interface_name_;
    const int PACKET_PROCESS_DELAY_MS_ = 1;
    pcap_t* pcap_handle_ = nullptr;
    bool live_capture_ = false;
  };

  using NetInterfacePtr = std::shared_ptr<NetInterface>;

  class NetInterfaceProcessor: public Gears::SimpleActiveObject
  {
  public:
    DECLARE_EXCEPTION(Exception, NetInterface::Exception);

  public:
    NetInterfaceProcessor(
      NetInterfacePtr interface,
      unsigned int threads = 1);

    virtual ~NetInterfaceProcessor();

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
    const NetInterfacePtr interface_;
    const int num_threads_;
    const std::string bpf_filter_;
    struct bpf_program bpf_code_;
    struct bpf_program* bpf_cfilter_ = NULL;
    pcap_t* pcap_handle_ = nullptr;

    std::mutex lock_;
    std::vector<std::unique_ptr<std::thread>> threads_;
  };

  using NetInterfaceProcessorPtr = std::shared_ptr<NetInterfaceProcessor>;
}

namespace dpi
{
  inline const std::string&
  NetInterface::interface_name() const
  {
    return interface_name_;
  }
}
