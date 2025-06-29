#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "AbortSessionHttpResource.hpp"

namespace dpi
{
  AbortSessionHttpResource::AbortSessionHttpResource(ManagerPtr manager)
    : manager_(std::move(manager))
  {}

  std::shared_ptr<httpserver::http_response>
  AbortSessionHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("session_id"))
      {
        const std::string session_id = request_json["session_id"].as_string();
        manager_->abort_session(session_id, true, false, true);
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
