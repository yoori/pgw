#pragma once

#include <memory>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <gears/ActiveObject.hpp>
#include <gears/CompositeActiveObject.hpp>

#include <dpi/Logger.hpp>
#include <dpi/UserStorage.hpp>
#include <dpi/EventProcessor.hpp>

namespace dpi
{
  class HttpServer: public Gears::CompositeActiveObject
  {
  public:
    HttpServer(
      LoggerPtr logger,
      UserStoragePtr user_storage,
      EventProcessorPtr event_processor,
      unsigned int port,
      std::string url_prefix
      );

    virtual void
    activate_object() override;

    virtual void
    deactivate_object() override;

    virtual void
    wait_object() override;

  private:
    struct WebServerHolder;
    using WebServerHolderPtr = std::shared_ptr<WebServerHolder>;

  private:
    LoggerPtr logger_;
    const EventProcessorPtr event_processor_;
    WebServerHolderPtr web_server_;
  };

  using HttpServerPtr = std::shared_ptr<HttpServer>;
}
