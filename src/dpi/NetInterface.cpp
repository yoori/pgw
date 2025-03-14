#include "NetInterface.hpp"

namespace dpi
{
  NetInterface::NetInterface(const char* interface_name)
  {
    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

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
      //capture_for = 0;
      //capture_until = 0;

      live_capture_ = false;
      //num_threads = 1; //< open pcap files in single threads mode

      // Trying to open a pcap file
      pcap_handle_ = pcap_open_offline(interface_name, pcap_error_buffer);
    }

    /*
    if (pcap_handle_ == NULL)
    {
      char filename[256] = "";

      if (strstr(interface_name, ".pcap"))
      {
        throw Exception(
          std::string("Could not open pcap file: ") + pcap_error_buffer);
      }

      // trying to open as a playlist as last attempt
      if (get_next_pcap_file_from_playlist(thread_id, filename, sizeof(filename)) == 0)
      {
        pcap_handle_ = pcap_open_offline(filename, pcap_error_buffer);
      }
    }
    */

    if (pcap_handle_ == NULL)
    {
      // this probably was a bad interface name, printing a generic error
      throw Exception(
        std::string("Could not open interface '") +
        interface_name + "': " + pcap_error_buffer);
    }

    // configure bpf filter
    if (pcap_handle_ && !bpf_filter_.empty())
    {
      if (!bpf_cfilter_)
      {
        if (pcap_compile(pcap_handle_, &bpf_code_, bpf_filter_.c_str(), 1, 0xFFFFFF00) < 0)
        {
          throw Exception(
            std::string("Can't compile pbf filter '") +
            bpf_filter_ + "': " + pcap_geterr(pcap_handle_));
        }

        bpf_cfilter_ = &bpf_code_;
      }

      if (pcap_setfilter(pcap_handle_, bpf_cfilter_) < 0)
      {
        throw Exception(
          std::string("Can't set pbf filter: ") + pcap_geterr(pcap_handle_));
      }
    }
  }

  bool NetInterface::live_capture() const
  {
    return live_capture_;
  }
}
