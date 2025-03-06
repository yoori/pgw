#include <fstream>
#include <rapidjson/document.h>

#include "Config.hpp"

namespace dpi
{
  Config Config::read(const std::string_view& file)
  {
    Config result;

    std::string config_text;
    std::ifstream config_file_istr(std::string(file).c_str());
    std::string line;
    while(std::getline(config_file_istr, line))
    {
      config_text += line;
    }

    rapidjson::Document document;
    document.Parse(config_text.c_str());
    if (document.HasMember("pcap_file"))
    {
      result.pcap_file = document["pcap_file"].GetString();
    }

    if (document.HasMember("dpi_interface"))
    {
      result.interface = document["dpi_interface"].GetString();
    }

    return result;
  }
}
