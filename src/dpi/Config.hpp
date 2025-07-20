#pragma once

#include <string>
#include <optional>
#include <vector>
#include <set>

#include "DiameterSession.hpp"
#include "DiameterPassAttribute.hpp"
#include "Attribute.hpp"
#include "Value.hpp"

namespace dpi
{
  struct DiameterUrl
  {
    struct RemoteEndpoint
    {
      std::string host;
      unsigned int port = 0;
    };

    std::vector<SCTPConnection::Endpoint> local_endpoints;
    std::vector<SCTPConnection::Endpoint> connect_endpoints;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
  };

  struct Config
  {
    struct GlobalProperty
    {
      std::string target_property_name;
      Value value;
    };

    struct RediusProperty
    {
      std::string target_property_name;
      std::string name;
      std::string vendor;
    };

    struct Radius
    {
      unsigned int listen_port = 0;
      std::string secret;
      std::string dictionary;
      std::vector<RediusProperty> radius_properties;
    };

    struct Diameter
    {
      std::optional<DiameterUrl> diameter_url;
      std::vector<DiameterPassAttribute> pass_attributes;
    };

    std::vector<GlobalProperty> global_properties;
    std::string pcap_file;
    std::string interface;
    std::string interface2;
    std::string dump_stat_root;
    std::string ip_rules_root;
    unsigned int http_port = 0;
    std::string pcc_config_file;
    std::string session_key_rule_config_file;

    std::optional<Radius> radius;
    std::optional<Diameter> gx;
    std::optional<Diameter> gy;
    std::string diameter_dictionary;

    static Config read(const std::string_view& file);
  };
}
