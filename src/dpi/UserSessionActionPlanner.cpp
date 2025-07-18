#include "CerrCallback.hpp"
#include "Manager.hpp"
#include "UserSessionActionPlanner.hpp"

namespace dpi
{
  class UserSessionActionPlanner::ProcessUserSessionTask: public Gears::TaskGoal
  {
  public:
    ProcessUserSessionTask(
      Gears::Planner_var planner,
      Gears::TaskRunner_var task_runner,
      UserSessionActionPlanner* user_session_action_planner,
      std::weak_ptr<UserSession> user_session)
      throw()
      : Gears::TaskGoal(task_runner),
        planner_(std::move(planner)),
        user_session_action_planner_(user_session_action_planner),
        user_session_(std::move(user_session))
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

  UserSessionActionPlanner::~UserSessionActionPlanner()
  {}

  void
  UserSessionActionPlanner::activate_object()
  {
    std::cout << "UserSessionActionPlanner::activate_object()" << std::endl;
    Gears::CompositeActiveObject::activate_object();
  }

  void
  UserSessionActionPlanner::set_manager(const std::shared_ptr<Manager>& manager)
  {
    manager_ = manager;
  }

  void
  UserSessionActionPlanner::add_user_session(
    const UserSessionPtr& user_session,
    const Gears::Time& next_check)
  {
    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() <<
      "] UserSessionActionPlanner::add_user_session(): next_check = " << next_check.gm_ft() << std::endl;

    const Gears::Time now = Gears::Time::get_time_of_day();
    auto task = std::make_shared<ProcessUserSessionTask>(
      planner_,
      task_runner_,
      this,
      user_session);

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
    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() <<
      "] UserSessionActionPlanner::check_user_session_(): msisdn = " << user_session.traits()->msisdn <<
      std::endl;

    const Gears::Time now = Gears::Time::get_time_of_day();
    bool revalidate_gx = false;
    bool revalidate_gy = false;

    {
      UserSession::RevalidateResult revalidate_result = user_session.revalidation();

      if (revalidate_result.revalidate_gx_time.has_value())
      {
        if (now >= *revalidate_result.revalidate_gx_time)
        {
          revalidate_gx = true;
        }
      }

      if (revalidate_result.revalidate_gy_time.has_value())
      {
        if (now >= *revalidate_result.revalidate_gy_time)
        {
          revalidate_gy = true;
        }
      }
    }

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() <<
      "] UserSessionActionPlanner::check_user_session_(): msisdn = " << user_session.traits()->msisdn <<
      ", revalidate_gx = " << revalidate_gx <<
      ", revalidate_gy = " << revalidate_gy <<
      std::endl;

    if (revalidate_gx || revalidate_gy)
    {
      auto manager = manager_.lock();
      if (manager)
      {
        manager->update_session(
          user_session,
          revalidate_gx,
          revalidate_gy,
          "timed revalidation",
          std::unordered_set<std::string>(),
          std::unordered_set<std::string>(),
          EventTriggerArray()
        );
      }
    }

    // evaluate next_revalidate_time after update
    std::optional<Gears::Time> next_revalidate_time;

    {
      UserSession::RevalidateResult revalidate_result = user_session.revalidation();

      if (revalidate_result.revalidate_gx_time.has_value())
      {
        next_revalidate_time = next_revalidate_time.has_value() ?
          std::min(*next_revalidate_time, *revalidate_result.revalidate_gx_time) :
          *revalidate_result.revalidate_gx_time;
      }

      if (revalidate_result.revalidate_gy_time.has_value())
      {
        next_revalidate_time = next_revalidate_time.has_value() ?
          std::min(*next_revalidate_time, *revalidate_result.revalidate_gy_time) :
          *revalidate_result.revalidate_gy_time;
      }
    }

    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() <<
      "] UserSessionActionPlanner::check_user_session_(): msisdn = " << user_session.traits()->msisdn <<
      ", next_revalidate_time = " << (
        next_revalidate_time.has_value() ? next_revalidate_time->gm_ft() : std::string("none")) <<
      std::endl;

    return next_revalidate_time.has_value() ? *next_revalidate_time : now + Gears::Time(60);
  }
}

