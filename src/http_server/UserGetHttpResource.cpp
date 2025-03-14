#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

#include "Utils.hpp"
#include "UserGetHttpResource.hpp"

namespace dpi
{
  UserGetHttpResource::UserGetHttpResource(UserStoragePtr user_storage)
    : user_storage_(std::move(user_storage))
  {}

  std::shared_ptr<httpserver::http_response>
  UserGetHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "GET")
    {
      const std::string msisdn = request.get_arg("msisdn");
      const Gears::Time now = Gears::Time::get_time_of_day();
      UserPtr user = user_storage_->get_user_by_msisdn(msisdn, now);

      if (user)
      {
        return generate_json_response(request, user->to_json_string());
      }
    }

    return generate_uri_not_found_response(request);
  }
}
