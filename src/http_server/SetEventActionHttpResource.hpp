#pragma once

#include <httpserver.hpp>

#include <dpi/UserStorage.hpp>

#include "HttpServer.hpp"

namespace dpi
{
  class SetEventActionHttpResource: public httpserver::http_resource
  {
  public:
    SetEventActionHttpResource(EventProcessorPtr event_processor);

    std::shared_ptr<httpserver::http_response>
    render(const httpserver::http_request& request) override;

  private:
    EventProcessorPtr event_processor_;
  };
}
