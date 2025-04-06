#include "Logger.hpp"

namespace dpi
{
  // StreamLogger
  StreamLogger::StreamLogger(std::ostream& out)
    : out_(out)
  {}

  void
  StreamLogger::log(std::string_view msg)
  {
    out_.write(msg.data(), msg.size());
    out_.flush();
  }

  // FileLogger
  FileLogger::FileLogger(std::string_view file_path)
    : file_(std::make_unique<std::ofstream>(std::string(file_path).c_str(), std::ios_base::app))
  {}

  void
  FileLogger::log(std::string_view msg)
  {
    std::string msg_copy(msg);
    msg_copy += "\n";
    file_->write(msg_copy.data(), msg_copy.size());
    file_->flush();
  }
}
