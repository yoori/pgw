#pragma once

namespace dpi
{
  struct Config
  {
    std::string pcap_file;
    std::string interface;

    static Config read(const std::string_view& file);
  };
}
