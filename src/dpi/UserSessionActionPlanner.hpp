#pragma once

#include <memory>

#include <gears/Planner.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/CompositeActiveObject.hpp>

#include <dpi/UserSession.hpp>

namespace dpi
{
  class Manager;

  class UserSessionActionPlanner: public Gears::CompositeActiveObject
  {
  public:
    UserSessionActionPlanner(
      unsigned int threads_count = 10,
      const Gears::Time& forced_check_period = Gears::Time(60));

    virtual ~UserSessionActionPlanner();

    void
    set_manager(const std::shared_ptr<Manager>& manager);

    void
    add_user_session(
      const UserSessionPtr& user_session,
      const std::optional<Gears::Time>& next_check);

    void
    activate_object() override;

  protected:
    class ProcessUserSessionTask;

  protected:
    Gears::Time
    check_user_session_(UserSession& user_session);

  private:
    std::weak_ptr<Manager> manager_;
    Gears::Planner_var planner_;
    Gears::TaskRunner_var task_runner_;
    const Gears::Time forced_check_period_;
  };

  using UserSessionActionPlannerPtr = std::shared_ptr<UserSessionActionPlanner>;
}
