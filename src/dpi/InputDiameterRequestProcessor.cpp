#include "AVPUtils.hpp"

#include "InputDiameterRequestProcessor.hpp"

namespace dpi
{
  InputDiameterRequestProcessor::InputDiameterRequestProcessor(
    std::string origin_host,
    std::string origin_realm,
    std::shared_ptr<DiameterSession> diameter_session,
    ManagerPtr manager)
    : gx_application_id_(16777238),
      origin_host_(std::move(origin_host)),
      origin_realm_(std::move(origin_realm)),
      diameter_session_(diameter_session),
      manager_(manager)
  {}

  void
  InputDiameterRequestProcessor::process(const Diameter::Packet& request)
  {
    if (request.header().commandCode() == 258 || // RAR
      request.header().commandCode() == 274 || // ASR
      request.header().commandCode() == 275 // STR
    )
    {
      std::string session_id;

      // find Session-Id(263)
      for (int i = 0; i < request.numberOfAVPs(); ++i)
      {
        const auto& avp = request.avp(i);
        if (avp.header().avpCode() == 263)
        {
          ByteArray ba = avp.data().toOctetString();
          session_id = std::string(reinterpret_cast<const char*>(&ba[0]), ba.size());
          break;
        }
      }

      if (request.header().commandCode() == 258)
      {
        std::cout << "[DIAMETER] Send response for RAR request" << std::endl;

        // check termination
        bool terminate = false;

        for (int i = 0; i < request.numberOfAVPs(); ++i)
        {
          const auto& avp = request.avp(i);
          if (avp.header().avpCode() == 1045) // AVP: Session-Release-Cause(1045)
          {
            terminate = true;
            break;
          }
        }

        auto rar_response_packet = generate_rar_response_packet_(session_id);
        auto diameter_session = diameter_session_.lock();
        if (diameter_session)
        {
          diameter_session->send_packet(rar_response_packet);
        }

        auto manager = manager_.lock();
        if (manager)
        {
          if (terminate)
          {
            manager->abort_session(session_id, true, false, true);
          }
          else
          {
            manager->update_session(session_id);
          }
        }
      }
      else if (request.header().commandCode() == 274 || request.header().commandCode() == 275)
      {
        std::cout << "[DIAMETER] Send response for ASR/STR request" << std::endl;

        auto asr_response_packet = generate_asr_response_packet_(session_id, request.header().commandCode());
        auto diameter_session = diameter_session_.lock();
        if (diameter_session)
        {
          diameter_session->send_packet(asr_response_packet);
        }

        auto manager = manager_.lock();
        if (manager)
        {
          manager->abort_session(session_id, true, false, true);
        }
      }
    }
    else
    {
      std::cout << "[DIAMETER] [ERROR] Input request (Command-Code = " << request.header().commandCode() <<
        ") that can't be processed" << std::endl;
    }
  }

  ByteArray
  InputDiameterRequestProcessor::generate_rar_response_packet_(const std::string& session_id) const
  {
    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(Diameter::Packet::Header::Flags())
          .setCommandCode(258)
          .setApplicationId(gx_application_id_)
          .setHBHIdentifier(0x7ddf9367)
          .setETEIdentifier(0xc15ecb12)
      );

    packet
      .addAVP(create_string_avp(263, session_id, std::nullopt, true)) // Session-Id(263)
      .addAVP(create_string_avp(264, origin_host_, std::nullopt, true)) // Origin-Host(264)
      .addAVP(create_string_avp(296, origin_realm_, std::nullopt, true)) // Origin-Realm(296)
      .addAVP(create_uint32_avp(268, 2001, std::nullopt, true)) // Result-Code(268)
      /*
      .addAVP(create_ipv4_avp(
        501,
        request.access_network_charging_ip_address,
        10415,
        true)) //< Access-Network-Charging-Address
      .addAVP(create_avp( //< Access-Network-Charging-Identifier-Gx(1022)
        1022,
        Diameter::AVP::Data()
        .addAVP(create_octets_avp(503, uint32_to_buf_(request.charging_id), 10415, true))
        //< Access-Network-Charging-Identifier-Value(503)
        ,
        10415,
        true
        ))
      */
      ;

    return packet.updateLength().deploy();
  }

  ByteArray
  InputDiameterRequestProcessor::generate_asr_response_packet_(
    const std::string& session_id,
    unsigned long command_code) const
  {
    auto packet = Diameter::Packet()
      .setHeader(
        Diameter::Packet::Header()
          .setCommandFlags(Diameter::Packet::Header::Flags())
          .setCommandCode(command_code)
          .setApplicationId(gx_application_id_)
          .setHBHIdentifier(0x7ddf9367)
          .setETEIdentifier(0xc15ecb12)
      );

    packet
      .addAVP(create_string_avp(263, session_id, std::nullopt, true)) // Session-Id(263)
      .addAVP(create_string_avp(264, origin_host_, std::nullopt, true)) // Origin-Host(264)
      .addAVP(create_string_avp(296, origin_realm_, std::nullopt, true)) // Origin-Realm(296)
      .addAVP(create_uint32_avp(268, 2001, std::nullopt, true)) // Result-Code(268)
      ;

    return packet.updateLength().deploy();
  }
}
