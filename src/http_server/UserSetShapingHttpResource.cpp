#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "UserSetShapingHttpResource.hpp"

namespace dpi
{
  UserSetShapingHttpResource::UserSetShapingHttpResource(UserStoragePtr user_storage)
    : user_storage_(std::move(user_storage))
  {}

  std::shared_ptr<httpserver::http_response>
  UserSetShapingHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("msisdn") &&
        request_json.contains("sessions") &&
        request_json.contains("bps"))
      {
        const std::string msisdn = request_json["msisdn"].as_string();
        std::vector<SessionKey> shape_sessions;
        for (const auto& session_obj : request_json["sessions"].array_range())
        {
          SessionKey session_key(
            session_obj.contains("traffic_type") ?
              session_obj["traffic_type"].as_string() : std::string(),
            session_obj.contains("category_type") ?
              session_obj["category_type"].as_string() : std::string()
          );

          shape_sessions.emplace_back(std::move(session_key));
        }

        uint64_t bps = request_json["bps"].as_integer<uint64_t>();

        UserPtr user = user_storage_->add_user(msisdn);
        user->set_shaping(shape_sessions, bps);

        return generate_json_response(request, "");
      }
      else
      {
        return generate_error_response(request, 400, "No msisdn, sessions or bps defined", "ERROR");
      }
    }

    return generate_uri_not_found_response(request);
  }
}
