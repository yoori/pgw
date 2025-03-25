#pragma once

namespace dpi
{
  struct Config
  {
    std::string pcap_file;
    std::string interface;
    std::string interface2;
    std::string dump_stat_root;
    std::string ip_rules_root;
    unsigned int http_port = 0;

    static Config read(const std::string_view& file);
  };
}
