#include <fstream>

#include "PccConfigProvider.hpp"

namespace dpi
{
  namespace
  {
    class CerrCallback: public Gears::ActiveObjectCallback
    {
    public:
      virtual void
      report_error(
        Severity,
        const Gears::SubString& description,
        const char* = 0)
        noexcept
      {
        std::cerr << description.str() << std::endl;
      }

      virtual
      ~CerrCallback() noexcept
      {}
    };
  }

  class PccConfigProvider::DumpConfigTask: public Gears::TaskGoal
  {
  public:
    DumpConfigTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      PccConfigProvider* pcc_config_provider)
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        pcc_config_provider_(pcc_config_provider)
    {}

    virtual void
    execute() throw()
    {
      Gears::Time next_check = pcc_config_provider_->dump_config_();
      planner_->schedule(shared_from_this(), next_check);
    }

  private:
    Gears::Planner_var planner_;
    PccConfigProvider* pcc_config_provider_;
  };

  PccConfigProvider::PccConfigProvider(const std::string_view& pcc_config_file_path)
    : pcc_config_dump_period_(Gears::Time(60))
  {
    pcc_config_ = PccConfig::read(pcc_config_file_path);

    Gears::ActiveObjectCallback_var callback(new CerrCallback());
    task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 1));
    add_child_object(task_runner_);
    planner_ = Gears::Planner_var(new Gears::Planner(callback));
    add_child_object(planner_);

    task_runner_->enqueue_task(
      std::make_shared<DumpConfigTask>(planner_, task_runner_, this));
  }

  ConstPccConfigPtr
  PccConfigProvider::get_config() const
  {
    std::shared_lock<std::shared_mutex> guard(lock_);
    return pcc_config_;
  }

  Gears::Time
  PccConfigProvider::dump_config_() const
  {
    ConstPccConfigPtr dump_config = get_config();
    dump_config->save(config_file_path_);
    return Gears::Time::get_time_of_day() + pcc_config_dump_period_;
  }
}
