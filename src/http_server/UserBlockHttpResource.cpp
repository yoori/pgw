#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "UserBlockHttpResource.hpp"

namespace dpi
{
  UserBlockHttpResource::UserBlockHttpResource(UserStoragePtr user_storage)
    : user_storage_(std::move(user_storage))
  {}

  std::shared_ptr<httpserver::http_response>
  UserBlockHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("msisdn"))
      {
        const std::string msisdn = request_json["msisdn"].as_string();
        SessionKey block_session_key(
          request_json.contains("traffic_type") ?
            request_json["traffic_type"].as_string() : std::string(),
          request_json.contains("category_type") ?
            request_json["category_type"].as_string() : std::string()
          );
        const Gears::Time block_timestamp = Gears::Time::get_time_of_day() + (
          request_json.contains("block_for") ?
          request_json["block_for"].as_integer<uint64_t>() : 60);
        UserPtr user = user_storage_->add_user(msisdn, 0);
        user->session_block(block_session_key, block_timestamp);

        return generate_json_response(request, "");
      }
      else
      {
        return generate_error_response(request, 400, "No msisdn defined", "ERROR");
      }
    }

    return generate_uri_not_found_response(request);
  }
}
