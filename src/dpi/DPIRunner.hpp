#pragma once

#include <memory>
#include <string>
#include <thread>

#include <gears/Exception.hpp>
#include <gears/ActiveObject.hpp>

#include "PacketProcessor.hpp"


namespace dpi
{
  class DPIRunner: public Gears::SimpleActiveObject
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    DPIRunner(
      std::string_view config_path,
      PacketProcessorPtr packet_processor);

    virtual void
    activate_object() override;

    virtual void
    deactivate_object() override;

    virtual void
    wait_object() override;

  private:
    void run_();

    void main_loop_();

  private:
    const std::string config_path_;
    const PacketProcessorPtr packet_processor_;
    std::shared_ptr<std::thread> thread_;
  };

  using DPIRunnerPtr = std::shared_ptr<DPIRunner>;
}
