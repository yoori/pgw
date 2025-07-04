#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "UpdateSessionHttpResource.hpp"

namespace dpi
{
  UpdateSessionHttpResource::UpdateSessionHttpResource(ManagerPtr manager)
    : manager_(std::move(manager))
  {}

  std::shared_ptr<httpserver::http_response>
  UpdateSessionHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("session_id"))
      {
        bool update_gx = !request_json.contains("gx") || request_json["gx"].as_bool();
        bool update_gy = !request_json.contains("gy") || request_json["gy"].as_bool();
        const std::string session_id = request_json["session_id"].as_string();
        manager_->update_session(session_id, update_gx, update_gy, "Update over http endpoint");
        return generate_json_response(request, "");
      }
      else
      {
        return generate_error_response(request, 400, "No session_id defined", "ERROR");
      }
    }

    return generate_uri_not_found_response(request);
  }
}
