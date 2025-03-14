#include <iostream>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include <gears/Tokenizer.hpp>
#include <gears/Time.hpp>
#include <gears/AsciiStringManip.hpp>

#include "Utils.hpp"

namespace dpi
{
  namespace
  {
    using DomainSeparators = const Gears::Ascii::Char1Category<'.'>;
  }

  std::optional<boost::uuids::uuid> get_cookie_uid(const httpserver::http_request& request)
  {
    try
    {
      auto uid_str = request.get_cookie("uid");
      return boost::lexical_cast<boost::uuids::uuid>(uid_str);
    }
    catch(...)
    {}

    return std::nullopt;
  }

  std::string get_cookie_domain(const httpserver::http_request& request)
  {
    std::string host;

    try
    {
      host = request.get_header("Host");
    }
    catch(...)
    {}

    if (!host.empty())
    {
      Gears::StringManip::Splitter<DomainSeparators, true> splitter(host);
      Gears::SubString token;
      std::vector<Gears::SubString> domain_parts;
      while(splitter.get_token(token))
      {
        domain_parts.emplace_back(token);
      }

      if (domain_parts.size() > 2)
      {
        return (++domain_parts.rbegin())->str() + "." + domain_parts.rbegin()->str();
      }
    }

    return std::string();
  }

  void set_uid(httpserver::http_response& response,
    const httpserver::http_request& request,
    const boost::uuids::uuid& uid)
  {
    const Gears::Time expire_period = Gears::Time::ONE_DAY * 400;
    Gears::Time expire_time = Gears::Time::get_time_of_day() + expire_period;
    auto cookie_domain = get_cookie_domain(request);
    response.with_header("Set-Cookie",
      std::string("uid=") + boost::lexical_cast<std::string>(uid) + "; "
      "Max-Age=" + std::to_string(expire_period.tv_sec) + "; "
      "Expires=" + Gears::cookie_date(expire_time, false) + "; " +
      (!cookie_domain.empty() ? std::string("Domain=") + cookie_domain + "; " : std::string()) +
      "Path=/; Secure; HttpOnly; SameSite=Lax");
  }

  std::unordered_set<unsigned long>
  get_http_comma_set_arg(const httpserver::http_request& request, std::string_view key)
  {
    std::unordered_set<unsigned long> ret;
    std::string s = request.get_arg(key);

    std::string::size_type prev_pos = 0, pos = 0;

    while((pos = s.find(", ", pos)) != std::string::npos)
    {
      std::string ss(s.substr(prev_pos, pos - prev_pos));
      if (!ss.empty())
      {
        ret.emplace(std::stoi(ss));
      }
      prev_pos = ++pos;
    }

    std::string ss(s.substr(prev_pos, pos - prev_pos));
    if (!ss.empty())
    {
      ret.emplace(std::stoi(ss));
    }

    return ret;
  }

  int
  get_http_int_arg(const httpserver::http_request& request, std::string_view key, int default_value)
  {
    try
    {
      auto value = request.get_arg(key);
      auto flat_value = value.get_flat_value();
      if (!flat_value.empty())
      {
        return std::stoi(std::string(flat_value));
      }
    }
    catch(...)
    {}

    return default_value;
  }

  std::optional<unsigned long>
  get_http_int_arg(const httpserver::http_request& request, std::string_view key)
  {
    try
    {
      auto value = request.get_arg(key);
      auto flat_value = value.get_flat_value();
      if (!flat_value.empty())
      {
        return std::stoi(std::string(flat_value));
      }
    }
    catch(...)
    {}

    return std::nullopt;
  }

  float
  get_http_float_arg(const httpserver::http_request& request, std::string_view key, float default_value)
  {
    try
    {
      auto value = request.get_arg(key);
      auto flat_value = value.get_flat_value();
      if (!flat_value.empty())
      {
        return std::stof(std::string(flat_value));
      }
    }
    catch(...)
    {}

    return default_value;
  }

  void fill_cors(httpserver::http_response& response, const std::string& origin)
  {
    response.with_header("Access-Control-Allow-Credentials", "true");
    response.with_header("Access-Control-Allow-Origin", origin);
    response.with_header("Access-Control-Expose-Headers", "*");
    response.with_header("X-Content-Type-Options", "nosniff");
    response.with_header("X-Frame-Options", "deny");
    response.with_header("X-Xss-Protection", "0");
    response.with_header("X-Processing-Server", "cpp");
  }

  void fill_cache(httpserver::http_response& response, bool cache)
  {
    if (cache)
    {
      response.with_header("Cache-Control", "public, max-age=3600");
    }
    else
    {
      response.with_header("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate");
      response.with_header("Pragma", "no-cache");
    }
  }

  void fill_cors(httpserver::http_response& response, const httpserver::http_request& request)
  {
    std::string origin;
    try
    {
      origin = request.get_header("Origin");
    }
    catch(...)
    {}

    response.with_header("Access-Control-Allow-Credentials", "true");
    response.with_header("Access-Control-Allow-Origin", origin);
    response.with_header("Access-Control-Expose-Headers", "*");
    response.with_header("X-Content-Type-Options", "nosniff");
    response.with_header("X-Frame-Options", "deny");
    response.with_header("X-Xss-Protection", "0");
  }

  void fill_options_cors(httpserver::http_response& response, const std::string& origin)
  {
    response.with_header("Cache-Control", "max-age=86400");
    response.with_header("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS,TRACE");
    response.with_header("Access-Control-Allow-Headers", "authorization, content-type, g-recaptcha-response, Cookie");
    fill_cors(response, origin);
  }

  void fill_options_cors(httpserver::http_response& response, const httpserver::http_request& request)
  {
    std::string origin;
    try
    {
      origin = request.get_header("Origin");
    }
    catch(...)
    {}

    fill_options_cors(response, origin);
  }

  std::shared_ptr<httpserver::http_response>
  generate_options_response(const httpserver::http_request& request)
  {
    std::shared_ptr<httpserver::http_response> response(new httpserver::string_response("", 200));
    fill_options_cors(*response, request);
    return response;
  }

  std::shared_ptr<httpserver::http_response>
  generate_error_response(
    const httpserver::http_request& request,
    int status,
    const std::string& message,
    const std::string& code)
  {
    if (status == 500)
    {
      std::ostringstream ostr;
      ostr << "[" << Gears::Time::get_time_of_day().gm_ft() << "] [ERROR] Error on request processing: " << message << std::endl;
      std::cerr << ostr.str() << std::flush;
    }

    std::shared_ptr<httpserver::http_response> resp(new httpserver::string_response(
      std::string("{\"status\": " + std::to_string(status) + ", "
        "\"code\": \"" + code + "\", \"error\": \"") + message + "\"}", status));
    fill_cors(*resp, request);
    fill_cache(*resp, false);
    return resp;
  }

  std::shared_ptr<httpserver::http_response>
  generate_uri_not_found_response(const httpserver::http_request& request)
  {
    std::shared_ptr<httpserver::http_response> resp(new httpserver::string_response("Uri not found", 404));
    fill_cors(*resp, request);
    fill_cache(*resp, false);
    return resp;
  }

  std::shared_ptr<httpserver::http_response>
  generate_json_response(
    const httpserver::http_request& request,
    const std::string& response_content,
    const std::optional<unsigned int>& status_code,
    bool cache)
  {
    std::shared_ptr<httpserver::http_response> resp(
      new httpserver::string_response(
        response_content,
        status_code.has_value() ? *status_code : (!response_content.empty() ? 200 : 204)));

    fill_cors(*resp, request);
    fill_cache(*resp, cache && !response_content.empty());

    if (!response_content.empty())
    {
      resp->with_header("Content-Type", "application/json");
    }

    return resp;
  }

  std::map<std::string, std::string> parse_query_string(std::string_view query_string)
  {
    std::map<std::string, std::string> result;

    if (!query_string.empty())
    {
      if (query_string[0] == '?')
      {
        query_string = query_string.substr(1);
      }

      Gears::StringManip::Splitter<Gears::Ascii::SepAmp, false> splitter(query_string);
      Gears::SubString token;
      while(splitter.get_token(token))
      {
        Gears::SubString mime_key;
        Gears::SubString mime_value;

        auto pos = token.find('=');
        if (pos == Gears::SubString::NPOS)
        {
          mime_key = token.str();
        }
        else
        {
          mime_key = token.substr(0, pos);
          mime_value = token.substr(pos + 1);
        }

        std::string key;
        std::string value;
        Gears::StringManip::mime_url_decode(mime_key, key);
        Gears::StringManip::mime_url_decode(mime_value, value);

        result.emplace(key, value);
      }
    }

    return result;
  }

  std::optional<unsigned long> get_ulong_arg(const httpserver::http_request& request, const char* arg_name)
  {
    std::string arg_str;
    try
    {
      arg_str = request.get_arg(arg_name);
    }
    catch(...)
    {}

    std::optional<unsigned long> arg_value;
    unsigned long p_arg_value;
    if (Gears::StringManip::str_to_int(arg_str, p_arg_value))
    {
      arg_value = p_arg_value;
    }

    return arg_value;
  }
}
