#include <string_view>
#include <gears/Tokenizer.hpp>
#include <gears/StringManip.hpp>
#include <httpserver.hpp>

#include "HttpServer.hpp"
#include "UserGetHttpResource.hpp"
#include "UserAddHttpResource.hpp"
#include "UserSessionAddHttpResource.hpp"
#include "UserSessionGetHttpResource.hpp"
#include "UserBlockHttpResource.hpp"
#include "SetEventActionHttpResource.hpp"
#include "UserSetShapingHttpResource.hpp"
#include "AbortSessionHttpResource.hpp"
#include "UpdateSessionHttpResource.hpp"

namespace dpi
{
  class HttpServer::WebServerHolder
  {
  public:
    WebServerHolder(
      LoggerPtr logger,
      UserStoragePtr user_storage,
      UserSessionStoragePtr user_session_storage,
      EventProcessorPtr event_processor,
      ManagerPtr manager,
      unsigned int port,
      std::string url_prefix,
      unsigned long max_threads = 32)
      : user_get_http_resource_(std::make_shared<UserGetHttpResource>(user_storage)),
        user_add_http_resource_(std::make_shared<UserAddHttpResource>(user_storage)),
        user_session_add_http_resource_(std::make_shared<UserSessionAddHttpResource>(
          user_storage, user_session_storage)),
        user_session_get_http_resource_(std::make_shared<UserSessionGetHttpResource>(
          user_session_storage)),
        user_block_http_resource_(std::make_shared<UserBlockHttpResource>(user_storage)),
        set_event_action_http_resource_(std::make_shared<SetEventActionHttpResource>(event_processor)),
        user_set_shaping_http_resource_(std::make_shared<UserSetShapingHttpResource>(user_storage)),
        abort_session_http_resource_(std::make_shared<AbortSessionHttpResource>(manager)),
        update_session_http_resource_(std::make_shared<UpdateSessionHttpResource>(manager)),
        ws(httpserver::create_webserver(port)
          .max_threads(max_threads)
          .put_processed_data_to_content()
          .file_upload_target(httpserver::FILE_UPLOAD_MEMORY_AND_DISK)
          .generate_random_filename_on_upload()
          .content_size_limit(200 * 1024 * 1024)
          )
    {
      ws.register_resource("/api/get_user", user_get_http_resource_.get());
      ws.register_resource("/api/add_user", user_add_http_resource_.get());
      ws.register_resource("/api/add_user_session", user_session_add_http_resource_.get());
      ws.register_resource("/api/get_user_session", user_session_get_http_resource_.get());
      ws.register_resource("/api/block_user", user_block_http_resource_.get());
      ws.register_resource("/api/set_event_action", set_event_action_http_resource_.get());
      ws.register_resource("/api/set_user_shaping", user_set_shaping_http_resource_.get());
      ws.register_resource("/api/abort_session", abort_session_http_resource_.get());
      ws.register_resource("/api/update_session", update_session_http_resource_.get());
    }

  private:
    const std::shared_ptr<httpserver::http_resource> user_get_http_resource_;
    const std::shared_ptr<httpserver::http_resource> user_add_http_resource_;
    const std::shared_ptr<httpserver::http_resource> user_session_add_http_resource_;
    const std::shared_ptr<httpserver::http_resource> user_session_get_http_resource_;
    const std::shared_ptr<httpserver::http_resource> user_block_http_resource_;
    const std::shared_ptr<httpserver::http_resource> set_event_action_http_resource_;
    const std::shared_ptr<httpserver::http_resource> user_set_shaping_http_resource_;
    const std::shared_ptr<httpserver::http_resource> abort_session_http_resource_;
    const std::shared_ptr<httpserver::http_resource> update_session_http_resource_;

  public:
    httpserver::webserver ws;
  };

  // HttpServer impl
  HttpServer::HttpServer(
    LoggerPtr logger,
    UserStoragePtr user_storage,
    UserSessionStoragePtr user_session_storage,
    EventProcessorPtr event_processor,
    ManagerPtr manager,
    unsigned int port,
    std::string url_prefix
    )
    : web_server_(std::make_shared<WebServerHolder>(
        logger,
        user_storage,
        user_session_storage,
        event_processor,
        manager,
        port,
        url_prefix,
        16 //< threads
        ))
  {
  }

  void
  HttpServer::activate_object()
  {
    web_server_->ws.start(false);
    Gears::CompositeActiveObject::activate_object();
  }

  void
  HttpServer::deactivate_object()
  {
    Gears::CompositeActiveObject::deactivate_object();
  }

  void
  HttpServer::wait_object()
  {
    web_server_->ws.stop();
    Gears::CompositeActiveObject::wait_object();
  }
}
