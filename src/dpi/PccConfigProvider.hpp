#pragma once

#include <memory>
#include <shared_mutex>

#include <gears/CompositeActiveObject.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/Planner.hpp>

#include "PccConfig.hpp"

namespace dpi
{
  class PccConfigProvider: public Gears::CompositeActiveObject
  {
  public:
    PccConfigProvider(const std::string_view& pcc_config_file_path);

    ConstPccConfigPtr get_config() const;

  protected:
    class DumpConfigTask;
    class ReadConfigTask;

  protected:
    Gears::Time dump_config_() const;

    Gears::Time read_config_();

  private:
    const std::string config_file_path_;
    const Gears::Time pcc_config_dump_period_;
    Gears::TaskRunner_var task_runner_;
    Gears::Planner_var planner_;

    mutable std::shared_mutex lock_;
    ConstPccConfigPtr pcc_config_;
  };

  using PccConfigProviderPtr = std::shared_ptr<PccConfigProvider>;
}
