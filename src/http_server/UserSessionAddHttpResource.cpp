#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "UserSessionAddHttpResource.hpp"

namespace dpi
{
  UserSessionAddHttpResource::UserSessionAddHttpResource(
    UserStoragePtr user_storage,
    UserSessionStoragePtr user_session_storage)
    : user_storage_(std::move(user_storage)),
      user_session_storage_(std::move(user_session_storage))
  {}

  std::shared_ptr<httpserver::http_response>
  UserSessionAddHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("msisdn") && request_json.contains("ip"))
      {
        const std::string msisdn = request_json["msisdn"].as_string();
        const std::string ip = request_json["ip"].as_string();

        UserSessionTraits user_session_traits;
        user_session_traits.framed_ip_address = string_to_ipv4_address(ip);
        if (request_json.contains("imsi"))
        {
          user_session_traits.imsi = request_json["imsi"].as_string();
        }

        UserPtr user = user_storage_->add_user(msisdn);
        UserSessionPtr user_session = user_session_storage_->add_user_session(
          user_session_traits,
          user
        );

        return generate_json_response(request, "");
      }
      else
      {
        return generate_error_response(request, 400, "No msisdn or ip defined", "ERROR");
      }
    }

    return generate_uri_not_found_response(request);
  }
}
