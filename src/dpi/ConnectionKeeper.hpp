#pragma once

#include <gears/CompositeActiveObject.hpp>
#include <gears/TaskRunner.hpp>
#include <gears/Planner.hpp>

#include "BaseConnection.hpp"

namespace dpi
{
  class ConnectionKeeper: public Gears::CompositeActiveObject
  {
  public:
    ConnectionKeeper(
      BaseConnectionPtr connection,
      const Gears::Time& connect_period = Gears::Time(1));

  protected:
    class ConnectTask;

  protected:
    Gears::Time connect_();

  private:
    const BaseConnectionPtr connection_;
    const Gears::Time connect_period_;
    Gears::TaskRunner_var task_runner_;
    Gears::Planner_var planner_;
  };
}
