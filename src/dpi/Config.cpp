#include <iostream>
#include <fstream>

#include <jsoncons/json.hpp>

#include "Config.hpp"

namespace dpi
{
  namespace
  {
    DiameterUrl
    read_diameter_url(const jsoncons::json& diameter_url_obj)
    {
      DiameterUrl result_diameter_url;

      if (diameter_url_obj.contains("local_endpoints"))
      {
        for (const auto& local_endpoint_json : diameter_url_obj["local_endpoints"].array_range())
        {
          result_diameter_url.local_endpoints.emplace_back(
            SCTPConnection::Endpoint(
              local_endpoint_json["host"].as_string(),
              local_endpoint_json.contains("port") ?
                local_endpoint_json["port"].as<unsigned int>() : 0
            ));
        }
      }

      std::vector<SCTPConnection::Endpoint> connect_endpoints;
      if (diameter_url_obj.contains("connect_endpoints"))
      {
        for (const auto& endpoint_json : diameter_url_obj["connect_endpoints"].array_range())
        {
          result_diameter_url.connect_endpoints.emplace_back(
            SCTPConnection::Endpoint(
              endpoint_json["host"].as_string(),
              endpoint_json["port"].as<unsigned int>()
            ));
        }
      }

      if (diameter_url_obj.contains("origin-host"))
      {
        result_diameter_url.origin_host = diameter_url_obj["origin-host"].as_string();
      }

      if (diameter_url_obj.contains("origin-realm"))
      {
        result_diameter_url.origin_realm = diameter_url_obj["origin-realm"].as_string();
      }

      if (diameter_url_obj.contains("destination-host"))
      {
        result_diameter_url.destination_host = diameter_url_obj["destination-host"].as_string();
      }

      if (diameter_url_obj.contains("destination-realm"))
      {
        result_diameter_url.destination_realm = diameter_url_obj["destination-realm"].as_string();
      }

      return result_diameter_url;
    }

    Config::Diameter
    read_diameter_config(const jsoncons::json& diameter_obj)
    {
      Config::Diameter result_diameter_config;
      if (diameter_obj.contains("diameter_url"))
      {
        result_diameter_config.diameter_url = read_diameter_url(diameter_obj["diameter_url"]);
      }

      if (diameter_obj.contains("pass_attributes"))
      { 
        for (const auto& pass_attribute_json : diameter_obj["pass_attributes"].array_range())
        {
          DiameterPassAttribute pass_attribute;
          pass_attribute.avp_path = pass_attribute_json["avp_path"].as_string();
          pass_attribute.source.name = pass_attribute_json["radius"]["name"].as_string();
          pass_attribute.source.vendor = pass_attribute_json["radius"].contains("vendor") ?
            pass_attribute_json["radius"]["vendor"].as_string() :
            std::string();

          result_diameter_config.pass_attributes.emplace_back(pass_attribute);
        }
      }

      return result_diameter_config;
    }
  }

  Config
  Config::read(const std::string_view& file)
  {
    Config result;

    std::string config_text;
    std::ifstream config_file_istr(std::string(file).c_str());
    std::string line;
    while(std::getline(config_file_istr, line))
    {
      config_text += line;
    }

    jsoncons::json config_json = jsoncons::json::parse(config_text);

    if (config_json.contains("pcap_file"))
    {
      result.pcap_file = config_json["pcap_file"].as_string();
    }

    if (config_json.contains("dpi_interface"))
    {
      result.interface = config_json["dpi_interface"].as_string();
    }

    if (config_json.contains("dpi_interface2"))
    {
      result.interface2 = config_json["dpi_interface2"].as_string();
    }

    if (config_json.contains("dump_stat_root"))
    {
      result.dump_stat_root = config_json["dump_stat_root"].as_string();
    }

    if (config_json.contains("ip_rules_root"))
    {
      result.ip_rules_root = config_json["ip_rules_root"].as_string();
    }

    if (config_json.contains("http_port"))
    {
      result.http_port = config_json["http_port"].as<unsigned int>();
    }

    if (config_json.contains("pcc_config_file"))
    {
      result.pcc_config_file = config_json["pcc_config_file"].as_string();
    }

    if (config_json.contains("radius"))
    {
      const auto& radius_obj = config_json["radius"];
      result.radius = Config::Radius();

      result.radius->listen_port = radius_obj.contains("listen_port") ?
        radius_obj["listen_port"].as<unsigned long>() :
        1813;

      if (radius_obj.contains("secret"))
      {
        result.radius->secret = radius_obj["secret"].as_string();
      }

      if (radius_obj.contains("dictionary"))
      {
        result.radius->dictionary = radius_obj["dictionary"].as_string();
      }
    }

    // gx
    if (config_json.contains("gx"))
    {
      result.gx = read_diameter_config(config_json["gx"]);
    }

    // gy
    if (config_json.contains("gy"))
    {
      result.gy = read_diameter_config(config_json["gy"]);
    }

    if (config_json.contains("diameter_dictionary"))
    {
      result.diameter_dictionary = config_json["diameter_dictionary"].as_string();
    }

    std::cout << "Pcc config path: " << result.pcc_config_file << std::endl;
    return result;
  }
}
