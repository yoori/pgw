#pragma once

#include <memory>

#include "UserSessionStorage.hpp"
#include "DiameterSession.hpp"
#include "Manager.hpp"

namespace dpi
{
  class InputDiameterRequestProcessor
  {
  public:
    InputDiameterRequestProcessor(
      std::string origin_host,
      std::string origin_realm,
      std::shared_ptr<DiameterSession> diameter_session,
      ManagerPtr manager);

    void
    process(const Diameter::Packet& packet);

  private:
    ByteArray
    generate_rar_response_packet_(
      const std::string& session_id,
      uint32_t hbh_identifier,
      uint32_t ete_identifier,
      unsigned int result_code) const;

    ByteArray
    generate_asr_response_packet_(
      const std::string& session_id,
      unsigned long command_code,
      uint32_t hbh_identifier,
      unsigned int result_code) const;

  private:
    const std::string origin_host_;
    const std::string origin_realm_;
    const unsigned long gx_application_id_;
    std::weak_ptr<DiameterSession> diameter_session_;
    std::weak_ptr<Manager> manager_;
  };
}
