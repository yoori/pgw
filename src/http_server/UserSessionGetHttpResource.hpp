#pragma once

#include <httpserver.hpp>

#include <dpi/UserStorage.hpp>
#include <dpi/UserSessionStorage.hpp>

#include "HttpServer.hpp"

namespace dpi
{
  class UserSessionGetHttpResource: public httpserver::http_resource
  {
  public:
    UserSessionGetHttpResource(
      UserSessionStoragePtr user_session_storage);

    std::shared_ptr<httpserver::http_response>
    render(const httpserver::http_request& request) override;

  private:
    UserSessionStoragePtr user_session_storage_;
  };
}
