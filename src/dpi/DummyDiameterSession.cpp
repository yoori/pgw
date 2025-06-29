#include "DummyDiameterSession.hpp"

namespace dpi
{
  // DummyDiameterSession
  void
  DummyDiameterSession::set_request_processor(RequestProcessor)
  {
  }

  void
  DummyDiameterSession::send_packet(const ByteArray&)
  {
  }

  DiameterSession::GxInitResponse
  DummyDiameterSession::send_gx_init(const Request&)
  {
    return GxInitResponse();
  }

  DiameterSession::GxUpdateResponse
  DummyDiameterSession::send_gx_update(
    const Request&,
    const GxUpdateRequest&)
  {
    return GxUpdateResponse();
  }

  DiameterSession::GxTerminateResponse
  DummyDiameterSession::send_gx_terminate(
    const Request&,
    const GxTerminateRequest&)
  {
    return GxTerminateResponse();
  }

  DiameterSession::GyResponse
  DummyDiameterSession::send_gy_init(const GyRequest&)
  {
    return GyResponse();
  }

  DiameterSession::GyResponse
  DummyDiameterSession::send_gy_update(const GyRequest&)
  {
    return GyResponse();
  }

  DiameterSession::GyResponse
  DummyDiameterSession::send_gy_terminate(const GyRequest&)
  {
    return GyResponse();
  }
}
