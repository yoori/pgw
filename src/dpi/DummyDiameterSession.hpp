#pragma once

#include "DiameterSession.hpp"

namespace dpi
{
  // DummyDiameterSession
  class DummyDiameterSession: public DiameterSession
  {
  public:
    void
    set_request_processor(RequestProcessor request_processor) override;

    void
    send_packet(const ByteArray& send_packet) override;

    GxInitResponse
    send_gx_init(const Request& request) override;

    GxUpdateResponse
    send_gx_update(
      const Request& request,
      const GxUpdateRequest& update_request) override;

    GxTerminateResponse
    send_gx_terminate(
      const Request& request,
      const GxTerminateRequest& terminate_request) override;

    GyResponse
    send_gy_init(const GyRequest& request) override;

    GyResponse
    send_gy_update(const GyRequest& request) override;

    GyResponse
    send_gy_terminate(const GyRequest& request) override;
  };
}
