#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <jsoncons/json.hpp>

#include <dpi/NetworkUtils.hpp>

#include "Utils.hpp"
#include "SetEventActionHttpResource.hpp"

namespace dpi
{
  SetEventActionHttpResource::SetEventActionHttpResource(EventProcessorPtr event_processor)
    : event_processor_(std::move(event_processor))
  {}

  std::shared_ptr<httpserver::http_response>
  SetEventActionHttpResource::render(const httpserver::http_request& request)
  {
    if (request.get_method() == "POST")
    {
      auto body = request.get_content();
      jsoncons::json request_json = jsoncons::json::parse(body);

      if (request_json.contains("event"))
      {
	const std::string event_name = request_json["event"].as_string();

        std::vector<EventProcessor::EventAction> event_actions;

        EventProcessor::EventAction event_action0;

	if (request_json.contains("log"))
        {
          event_action0.log = request_json["log"].as_bool();
        }

	if (request_json.contains("block_current_session"))
        {
          event_action0.block_current_session = request_json["block_current_session"].as_bool();
        }

        event_actions.emplace_back(event_action0);

	if (request_json.contains("block_sessions"))
        {
          for (const auto& block_obj : request_json["block_sessions"].array_range())
          {
            if (block_obj.contains("traffic_type") && block_obj["traffic_type"].as_string() == "remote-control")
            {
              const std::vector<SessionKey> block_keys = {
                SessionKey("rdp", ""),
                SessionKey("anydesk", ""),
                SessionKey("tls", "anydesk")
              };

              for (const auto& block_key : block_keys)
              {
                EventProcessor::EventAction event_action;
                event_action.block_current_session = false;

                EventProcessor::BlockSession block_session;
                block_session.session_key = block_key;
                block_session.block_for = Gears::Time(
                  block_obj.contains("block_for") ?
                  block_obj["block_for"].as_integer<uint64_t>() : 60);

                event_action.block_session = block_session;
                event_actions.emplace_back(event_action);
              }
            }
            else
            {
              EventProcessor::EventAction event_action;
              event_action.block_current_session = false;

              EventProcessor::BlockSession block_session;
              block_session.session_key = SessionKey(
                block_obj.contains("traffic_type") ?
                  block_obj["traffic_type"].as_string() : std::string(),
                block_obj.contains("category_type") ?
                  block_obj["category_type"].as_string() : std::string()
              );
              block_session.block_for = Gears::Time(
                block_obj.contains("block_for") ?
                block_obj["block_for"].as_integer<uint64_t>() : 60);

              event_action.block_session = block_session;
              event_actions.emplace_back(event_action);
            }
          }
        }

        event_processor_->set_event_action(event_name, event_actions);

        return generate_json_response(request, "");
      }
      else
      {
        return generate_error_response(request, 400, "No event defined", "ERROR");
      }
    }

    return generate_uri_not_found_response(request);
  }
}
