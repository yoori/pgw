#include "ConnectionKeeper.hpp"

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

  // ConnectionKeeper::ConnectTask
  class ConnectionKeeper::ConnectTask: public Gears::TaskGoal
  {
  public:
    ConnectTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      ConnectionKeeper* connection_keeper)
      throw()
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        connection_keeper_(connection_keeper)
    {}

    virtual void
    execute() throw()
    {
      Gears::Time next_check = connection_keeper_->connect_();
      planner_->schedule(shared_from_this(), next_check);
    }

  private:
    Gears::Planner_var planner_;
    ConnectionKeeper* connection_keeper_;
  };

  // ConnectionKeeper
  ConnectionKeeper::ConnectionKeeper(
    BaseConnectionPtr connection,
    const Gears::Time& connect_period)
    : connection_(std::move(connection)),
      connect_period_(connect_period)
  {
    Gears::ActiveObjectCallback_var callback(new CerrCallback());
    task_runner_ = Gears::TaskRunner_var(new Gears::TaskRunner(callback, 1));
    add_child_object(task_runner_);
    planner_ = Gears::Planner_var(new Gears::Planner(callback));
    add_child_object(planner_);

    task_runner_->enqueue_task(
      std::make_shared<ConnectTask>(planner_, task_runner_, this));
  }

  Gears::Time
  ConnectionKeeper::connect_()
  {
    try
    {
      connection_->lock()->connect();
      std::cerr << "Reconnected" << std::endl;
    }
    catch(const Gears::Exception& ex)
    {
      std::cerr << "Can't reconnect: " << ex.what() << std::endl;
    }

    return Gears::Time::get_time_of_day() + connect_period_;
  }
}
