#pragma once

#include <memory>

#include <gears/Planner.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/CompositeActiveObject.hpp>

#include <dpi/UserSession.hpp>

namespace dpi
{
  class UserSessionActionPlanner: public Gears::CompositeActiveObject
  {
  public:
    UserSessionActionPlanner(unsigned int threads_count = 10);

    void
    add_user_session(
      const UserSessionPtr& user_session,
      const Gears::Time& next_check);

  protected:
    class ProcessUserSessionTask;

  protected:
    Gears::Time
    check_user_session_(UserSession& user_session);

  private:
    Gears::Planner_var planner_;
    Gears::TaskRunner_var task_runner_;
  };

  using UserSessionActionPlannerPtr = std::shared_ptr<UserSessionActionPlanner>;
}
