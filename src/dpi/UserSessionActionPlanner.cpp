#include "CerrCallback.hpp"
#include "UserSessionActionPlanner.hpp"

namespace dpi
{
  class UserSessionActionPlanner::ProcessUserSessionTask: public Gears::TaskGoal
  {
  public:
    ProcessUserSessionTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      UserSessionActionPlanner* user_session_action_planner)
      throw()
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        user_session_action_planner_(user_session_action_planner)
    {}

    void
    execute() noexcept override
    {
      auto user_session = user_session_.lock();
      if (user_session)
      {
        Gears::Time next_check = user_session_action_planner_->check_user_session_(*user_session);
        if (next_check != Gears::Time::ZERO)
        {
          planner_->schedule(shared_from_this(), next_check);
        }
      }
    }

  private:
    Gears::Planner_var planner_;
    UserSessionActionPlanner* user_session_action_planner_;
    std::weak_ptr<UserSession> user_session_;
  };

  UserSessionActionPlanner::UserSessionActionPlanner(
    unsigned int threads_count)
    : planner_(std::make_shared<Gears::Planner>(std::make_shared<CerrCallback>())),
      task_runner_(std::make_shared<Gears::TaskRunner>(std::make_shared<CerrCallback>(), threads_count))
  {
    add_child_object(planner_);
    add_child_object(task_runner_);
  }

  void
  UserSessionActionPlanner::add_user_session(
    const UserSessionPtr& user_session,
    const Gears::Time& next_check)
  {
    const Gears::Time now = Gears::Time::get_time_of_day();
    auto task = std::make_shared<ProcessUserSessionTask>(planner_, task_runner_, this);

    if (next_check <= now)
    {
      task_runner_->enqueue_task(task);
    }
    else
    {
      planner_->schedule(task, next_check);
    }
  }

  Gears::Time
  UserSessionActionPlanner::check_user_session_(UserSession& user_session)
  {
    return Gears::Time::ZERO;
  }
}

