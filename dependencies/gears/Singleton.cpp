#include <cstdlib>

#include <gears/Singleton.hpp>

namespace Gears
{
  //
  // AtExitDestroying class
  //

  // All of these are initialized statically
  Gears::Mutex AtExitDestroying::mutex_;
  AtExitDestroying* AtExitDestroying::lower_priority_head_ = 0;
  bool AtExitDestroying::registered_ = false;

  AtExitDestroying::AtExitDestroying(int priority) noexcept
    : priority_(priority)
  {
    Gears::Mutex::WriteGuard guard(mutex_);
    if (!registered_)
    {
      registered_ = !std::atexit(destroy_at_exit_);
    }
    AtExitDestroying** pptr = &lower_priority_head_;
    while (*pptr && (*pptr)->priority_ < priority_)
    {
      pptr = &(*pptr)->lower_priority_;
    }
    if (*pptr && (*pptr)->priority_ == priority_)
    {
      lower_priority_ = (*pptr)->lower_priority_;
      //(*pptr)->lower_priority_ = 0;
      equal_priority_ = *pptr;
      *pptr = this;
    }
    else
    {
      equal_priority_ = 0;
      lower_priority_ = *pptr;
      *pptr = this;
    }
  }

  void
  AtExitDestroying::destroy_at_exit_() noexcept
  {
    Gears::Mutex::WriteGuard guard(mutex_);
    for (AtExitDestroying* current_priority = lower_priority_head_;
      current_priority;)
    {
      AtExitDestroying* next_priority = current_priority->lower_priority_;
      for (AtExitDestroying* current = current_priority; current;)
      {
        AtExitDestroying* next = current->equal_priority_;
        delete current;
        current = next;
      }
      current_priority = next_priority;
    }
  }
}
