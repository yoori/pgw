#pragma once

#include <httpserver.hpp>

#include <dpi/UserStorage.hpp>

#include "HttpServer.hpp"

namespace dpi
{
  class UserBlockHttpResource: public httpserver::http_resource
  {
  public:
    UserBlockHttpResource(UserStoragePtr user_storage);

    std::shared_ptr<httpserver::http_response>
    render(const httpserver::http_request& request) override;

  private:
    UserStoragePtr user_storage_;
  };
}
