#pragma once

#include <gears/TaskRunner.hpp>

namespace dpi
{
  // FunTask
  class FunTask: public Gears::Task
  {
  public:
    FunTask(std::function<void()> fun) throw()
      : fun_(fun)
    {}

    virtual void
    execute() throw()
    {
      fun_();
    }

  private:
    std::function<void()> fun_;
  };
}
