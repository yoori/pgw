#pragma once

#include "RadiusServer.hpp"
#include "Processor.hpp"

namespace dpi
{
  class RadiusServerImpl: public RadiusServer
  {
  public:
    RadiusServerImpl(
      boost::asio::io_service& io_service,
      const std::string& secret,
      uint16_t port,
      const std::string& dictionary_file_path,
      dpi::ProcessorPtr processor);

  protected:
    virtual std::optional<RadProto::Packet>
    process_packet_(const RadProto::Packet&) override;

  protected:
    dpi::ProcessorPtr processor_;
  };
}
