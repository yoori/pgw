#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "UserSessionGetHttpResource.hpp"

namespace dpi
{
  UserSessionGetHttpResource::UserSessionGetHttpResource(
    UserSessionStoragePtr user_session_storage)
    : user_session_storage_(std::move(user_session_storage))
  {}

  std::shared_ptr<httpserver::http_response>
  UserSessionGetHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "GET")
    {
      const std::string ip = request.get_arg("ip");

      auto framed_ip_address = string_to_reversed_ipv4_address(ip);

      UserSessionPtr user_session = user_session_storage_->get_user_session_by_ip(
        framed_ip_address
      );

      if (!user_session)
      {
        return generate_error_response(request, 404, "No session", "ERROR");
      }

      const auto now = Gears::Time::get_time_of_day();

      jsoncons::json response_json;
      response_json["msisdn"] = user_session->traits()->msisdn;
      auto used_limits = user_session->get_gy_used_limits(now, false);

      std::vector<jsoncons::json> used_limit_jsons;
      for (const auto& used_limit : used_limits)
      {
        jsoncons::json used_limit_json;
        used_limit_json["rule_id"] = used_limit.rule_id;
        used_limit_json["reporting_reason"] = used_limit.reporting_reason.has_value() ?
          std::optional<unsigned int>(static_cast<unsigned int>(*used_limit.reporting_reason)) :
          std::nullopt;
        used_limit_json["total_octets"] = used_limit.total_octets;
        used_limit_json["output_octets"] = used_limit.output_octets;
        used_limit_json["input_octets"] = used_limit.input_octets;
        used_limit_jsons.emplace_back(std::move(used_limit_json));
      }

      response_json["used_limits"] = used_limit_jsons;

      jsoncons::json_options json_print_options;
      std::string res;
      jsoncons::encode_json(response_json, res, json_print_options, jsoncons::indenting::indent);
      return generate_json_response(request, res);
    }

    return generate_uri_not_found_response(request);
  }
}
