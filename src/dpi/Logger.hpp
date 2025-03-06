#pragma once

#include <memory>
#include <string>
#include <fstream>

namespace dpi
{
  class Logger
  {
  public:
    virtual void log(std::string_view msg) = 0;
  };

  class StreamLogger: public Logger
  {
  public:
    StreamLogger(std::ostream& out);

    virtual void log(std::string_view msg) override;

  private:
    std::ostream& out_;
  };

  class FileLogger: public Logger
  {
  public:
    FileLogger(std::string_view file);

    virtual void log(std::string_view msg) override;

  private:
    std::unique_ptr<std::ofstream> file_;
  };

  using LoggerPtr = std::shared_ptr<Logger>;
}
