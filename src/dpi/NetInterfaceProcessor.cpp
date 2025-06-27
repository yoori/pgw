#include <sstream>

#include "NetInterfaceProcessor.hpp"

namespace dpi
{
  namespace
  {
    const int LINKTYPE_LINUX_SLL2 = 276;

    int ndpi_is_datalink_supported(int datalink_type)
    {
      // keep in sync with the similar switch in ndpi_workflow_process_packet
      switch(datalink_type)
      {
        case DLT_NULL:
        case DLT_PPP_SERIAL:
        case DLT_C_HDLC:
        case DLT_PPP:
#       ifdef DLT_IPV4
        case DLT_IPV4:
#       endif
#       ifdef DLT_IPV6
        case DLT_IPV6:
#       endif
        case DLT_EN10MB:
        case DLT_LINUX_SLL:
        case DLT_IEEE802_11_RADIO:
        case DLT_RAW:
        case DLT_PPI:
        case LINKTYPE_LINUX_SLL2:
          return 1;
        default:
          return 0;
      }
    }
  }

  NetInterface::NetInterface(
    const char* interface_name)
    : interface_name_(interface_name)
  {}

  // PcapNetInterface impl
  PcapNetInterface::PcapNetInterface(
    const char* interface_name,
    unsigned int snaplen)
    : NetInterface(interface_name)
  {
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    //std::cout << "NetInterface: snaplen = " << snaplen << std::endl;

    // Trying to open the interface
    if ((pcap_handle_ = pcap_open_live(
      interface_name,
      snaplen,
      promisc,
      PACKET_PROCESS_DELAY_MS_,
      pcap_error_buffer)) != NULL)
    {
      live_capture_ = true;
    }

    // try to open as file or playlist.
    if (pcap_handle_ == NULL)
    {
      live_capture_ = false;

      // trying to open a pcap file
      pcap_handle_ = pcap_open_offline(interface_name, pcap_error_buffer);
    }

    if (pcap_handle_ == NULL)
    {
      // this probably was a bad interface name, printing a generic error
      throw Exception(
        std::string("Could not open interface '") +
        interface_name + "': " + pcap_error_buffer);
    }
  }

  PcapNetInterface::~PcapNetInterface() noexcept
  {
    if (pcap_handle_)
    {
      pcap_close(pcap_handle_);
      pcap_handle_ = NULL;
    }
  }

  pcap_t*
  PcapNetInterface::pcap_handle() const
  {
    return pcap_handle_;
  }

  void
  PcapNetInterface::send(const void* packet_buf, int packet_buf_size)
  {
    /*
    int ret = pcap_inject(pcap_handle_, packet_buf, packet_buf_size);

    if (ret == PCAP_ERROR)
    {
      std::ostringstream ostr;
      ostr << "Error on packet sending(size = " << packet_buf_size << "): " << pcap_geterr(pcap_handle_);
      throw Exception(ostr.str());
    }

    if (ret < packet_buf_size)
    {
      std::ostringstream ostr;
      ostr << "Error on packet sending, sent only part of packet: " << ret << "/" << packet_buf_size;
      throw Exception(ostr.str());
    }
    */

    int ret = pcap_sendpacket(pcap_handle_, static_cast<const u_char*>(packet_buf), packet_buf_size);

    if (ret < 0)
    {
      std::ostringstream ostr;
      ostr << "Error on packet sending(size = " << packet_buf_size << "): " << pcap_geterr(pcap_handle_);
      throw Exception(ostr.str());
    }
  }

  bool
  PcapNetInterface::live_capture() const
  {
    return live_capture_;
  }

  // NetInterfaceProcessor impl
  NetInterfaceProcessor::NetInterfaceProcessor(
    NetInterfacePtr interface,
    unsigned int num_threads)
    : interface_(std::move(interface)),
      num_threads_(num_threads)
  {
    pcap_t* pcap_handle = interface_->pcap_handle();

    // configure bpf filter
    if (pcap_handle && !bpf_filter_.empty())
    {
      if (!bpf_cfilter_)
      {
        if (pcap_compile(pcap_handle, &bpf_code_, bpf_filter_.c_str(), 1, 0xFFFFFF00) < 0)
        {
          throw Exception(
            std::string("Can't compile pbf filter '") +
            bpf_filter_ + "': " + pcap_geterr(pcap_handle));
        }

        bpf_cfilter_ = &bpf_code_;
      }

      if (pcap_setfilter(pcap_handle, bpf_cfilter_) < 0)
      {
        throw Exception(
          std::string("Can't set pbf filter: ") + pcap_geterr(pcap_handle));
      }
    }
  }

  NetInterfaceProcessor::~NetInterfaceProcessor()
  {
    if (bpf_cfilter_)
    {
      pcap_freecode(bpf_cfilter_);
      bpf_cfilter_ = 0;
    }
  }

  void NetInterfaceProcessor::activate_object_()
  {
    for (unsigned int thread_i = 0; thread_i < num_threads_; ++thread_i)
    {
      threads_.emplace_back(
        std::make_unique<std::thread>(
          &NetInterfaceProcessor::processing_thread, this, thread_i));
    }
  }

  void NetInterfaceProcessor::deactivate_object_()
  {
    pcap_t* pcap_handle = interface_->pcap_handle();

    if (pcap_handle)
    {
      pcap_breakloop(pcap_handle);
    }
  }

  void NetInterfaceProcessor::wait_object_()
  {
    for (const auto& thread_ptr : threads_)
    {
      thread_ptr->join();
    }
  }

  void NetInterfaceProcessor::ndpi_process_packet_(
    u_char* args,
    const struct pcap_pkthdr* header,
    const u_char* packet)
  {
    ProcessingContext* processing_context = (ProcessingContext*)args;
    processing_context->interface_processor->process_packet(
      processing_context->thread_i,
      header,
      packet);
  }

  void NetInterfaceProcessor::processing_thread(unsigned int thread_i)
  {
#if defined(__linux__) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int core_i = thread_i % num_cores;
    CPU_SET(core_i, &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
    {
      std::ostringstream ostr;
      ostr << "Error while binding thread " << thread_i << " to core " << core_i;
      throw Exception(ostr.str());
    }
#endif

    pcap_t* pcap_handle = interface_->pcap_handle();

    if (pcap_handle)
    {
      int datalink_type = pcap_datalink(pcap_handle);

      if (!ndpi_is_datalink_supported(datalink_type))
      {
        std::ostringstream ostr;
        ostr << "Unsupported datalink " << datalink_type << ". Skip pcap";
        throw Exception(ostr.str());
      }

      ProcessingContext processing_context;
      processing_context.interface_processor = this;
      processing_context.thread_i = thread_i;

      int ret = pcap_loop(
        pcap_handle,
        -1,
        &NetInterfaceProcessor::ndpi_process_packet_,
        (u_char*)&processing_context);

      if (ret == -1)
      {
        std::ostringstream ostr;
        ostr << "Error while reading pcap file: " << pcap_geterr(pcap_handle);
        throw Exception(ostr.str());
      }
    }
  }

  void NetInterfaceProcessor::process_packet(
    unsigned int /*thread_i*/,
    const struct pcap_pkthdr* /*header*/,
    const u_char* /*packet*/)
  {}
}
