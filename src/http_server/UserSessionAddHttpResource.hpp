#pragma once

#include <httpserver.hpp>

#include <dpi/UserStorage.hpp>
#include <dpi/UserSessionStorage.hpp>

#include "HttpServer.hpp"

namespace dpi
{
  class UserSessionAddHttpResource: public httpserver::http_resource
  {
  public:
    UserSessionAddHttpResource(
      UserStoragePtr user_storage,
      UserSessionStoragePtr user_session_storage);

    std::shared_ptr<httpserver::http_response>
    render(const httpserver::http_request& request) override;

  private:
    UserStoragePtr user_storage_;
    UserSessionStoragePtr user_session_storage_;
  };
}
