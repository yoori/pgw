#pragma once

#include <optional>

#include <boost/asio.hpp>

#include <radproto/socket.h>
#include <radproto/packet.h>
#include <radproto/dictionaries.h>

#include <dpi/Value.hpp>
#include <dpi/RadiusUserSessionPropertyExtractor.hpp>

#include "Processor.hpp"

namespace dpi
{
  class RadiusServer
  {
  public:
    RadiusServer(
      boost::asio::io_service& io_service,
      uint16_t listen_port,
      const std::string& secret,
      const std::string& dictionary_file_path,
      ProcessorPtr processor,
      RadiusUserSessionPropertyExtractorPtr radius_user_session_property_extractor);

  private:
    void handle_receive_(
      const boost::system::error_code& error,
      const std::optional<RadProto::Packet>& packet,
      const boost::asio::ip::udp::endpoint& source);

    void handle_send(const boost::system::error_code& ec);

    static Value attribute_to_value_(const RadProto::Attribute& attribute);

  private:
    struct ResolveAttribute
    {
      ConstAttributeKeyPtr attribute_key;
      RadProto::Dictionaries::AttributeKey resolve_attribute_key;
    };

    using ResolveAttributeArray = std::vector<ResolveAttribute>;

  protected:
    std::optional<RadProto::Packet>
    process_packet_(const RadProto::Packet&);

  protected:
    RadProto::Socket radius_;
    RadProto::Dictionaries dictionaries_;
    const std::string secret_;
    const dpi::ProcessorPtr processor_;
    ResolveAttributeArray pass_attribute_keys_;
    const RadiusUserSessionPropertyExtractorPtr radius_user_session_property_extractor_;
  };
}
