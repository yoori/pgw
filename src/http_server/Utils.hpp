#pragma once

#include <string>
#include <unordered_set>
#include <optional>

#include <boost/uuid/uuid.hpp>
#include "httpserver.hpp"

#include <gears/Time.hpp>

namespace dpi
{
  std::map<std::string, std::string> parse_query_string(std::string_view query_string);

  int get_http_int_arg(const httpserver::http_request& request, std::string_view key, int default_value);

  float get_http_float_arg(const httpserver::http_request& request, std::string_view key, float default_value);

  std::optional<unsigned long> get_http_int_arg(const httpserver::http_request& request, std::string_view key);

  std::unordered_set<unsigned long>
  get_http_comma_set_arg(const httpserver::http_request& request, std::string_view key);

  void fill_cache(httpserver::http_response& response, bool cache);

  void fill_cors(httpserver::http_response& response, const std::string& origin);

  void fill_cors(httpserver::http_response& response, const httpserver::http_request& request);

  void fill_options_cors(httpserver::http_response& response, const std::string& origin);

  void fill_options_cors(httpserver::http_response& response, const httpserver::http_request& request);

  std::string get_cookie_domain(const httpserver::http_request& request);

  std::optional<boost::uuids::uuid> get_cookie_uid(const httpserver::http_request& request);

  void set_uid(httpserver::http_response& response,
    const httpserver::http_request& request,
    const boost::uuids::uuid& uid);

  // Response generators.
  std::shared_ptr<httpserver::http_response>
  generate_options_response(const httpserver::http_request& request);

  std::shared_ptr<httpserver::http_response>
  generate_error_response(const httpserver::http_request& request,
    int status, const std::string& message, const std::string& code);

  std::shared_ptr<httpserver::http_response>
  generate_uri_not_found_response(const httpserver::http_request& request);

  std::shared_ptr<httpserver::http_response>
  generate_json_response(
    const httpserver::http_request& request,
    const std::string& response_content,
    const std::optional<unsigned int>& status_code = std::nullopt,
    bool cache = false);

  std::optional<unsigned long> get_ulong_arg(
    const httpserver::http_request& request, const char* arg_name);
}
