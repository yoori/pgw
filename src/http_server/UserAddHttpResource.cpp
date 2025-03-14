#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "UserAddHttpResource.hpp"

namespace dpi
{
  UserAddHttpResource::UserAddHttpResource(UserStoragePtr user_storage)
    : user_storage_(std::move(user_storage))
  {}

  std::shared_ptr<httpserver::http_response>
  UserAddHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("msisdn") && request_json.contains("ip"))
      {
        const std::string msisdn = request_json["msisdn"].as_string();
        const std::string ip = request_json["ip"].as_string();
        user_storage_->add_user(msisdn, string_to_ipv4_address(ip));
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
