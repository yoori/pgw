#pragma once

#include <httpserver.hpp>

#include <dpi/UserStorage.hpp>

#include "HttpServer.hpp"

namespace dpi
{
  class UserAddHttpResource: public httpserver::http_resource
  {
  public:
    UserAddHttpResource(UserStoragePtr user_storage);

    std::shared_ptr<httpserver::http_response>
    render(const httpserver::http_request& request) override;

  private:
    UserStoragePtr user_storage_;
  };
}
