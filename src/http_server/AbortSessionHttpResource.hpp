#pragma once

#include <httpserver.hpp>

#include <dpi/UserStorage.hpp>

#include "HttpServer.hpp"

namespace dpi
{
  class AbortSessionHttpResource: public httpserver::http_resource
  {
  public:
    AbortSessionHttpResource(ManagerPtr manager);

    std::shared_ptr<httpserver::http_response>
    render(const httpserver::http_request& request) override;

  private:
    ManagerPtr manager_;
  };
}
