#pragma once

#include <string>
#include <optional>
#include <vector>

#include "DiameterSession.hpp"

namespace dpi
{
  struct DiameterUrl
  {
    struct RemoteEndpoint
    {
      std::string host;
      unsigned int port = 0;
    };

    std::vector<DiameterSession::Endpoint> local_endpoints;
    std::vector<DiameterSession::Endpoint> connect_endpoints;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
  };

  struct Config
  {
    std::string pcap_file;
    std::string interface;
    std::string interface2;
    std::string dump_stat_root;
    std::string ip_rules_root;
    unsigned int http_port = 0;
    std::optional<DiameterUrl> gx_diameter_url;
    std::optional<DiameterUrl> gy_diameter_url;

    static Config read(const std::string_view& file);
  };
}
