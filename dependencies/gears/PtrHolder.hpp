#ifndef GEARS_PTRHOLDER_HPP
#define GEARS_PTRHOLDER_HPP

#include <memory>
#include <gears/Lock.hpp>
#include <gears/Uncopyable.hpp>

namespace Gears
{
  /**
   * Safe holder for a pointer. Allows serialized "get" and assignment
   * operations on stored RC object pointer.
   * SmartPtr is a type of "get" operation return value (defines pointer
   * type as well).
   */
  template <typename SmartPtr>
  class PtrHolder : private Gears::Uncopyable
  {
  public:
    typedef typename SmartPtr::Type Type;

    explicit
    PtrHolder(std::nullptr_t ptr = nullptr) /*throw (Gears::Exception)*/;

    template <typename Other>
    explicit
    PtrHolder(Other&& sptr) /*throw (Gears::Exception)*/;

    ~PtrHolder() noexcept;

    template <typename Other>
    PtrHolder&
    operator =(Other&& sptr) /*throw (Gears::Exception)*/;

    SmartPtr
    get() /*throw (Gears::Exception)*/;

    const SmartPtr
    get() const /*throw (Gears::Exception)*/;

  private:
    mutable Gears::SpinLock mutex_;
    SmartPtr ptr_;
  };
}

namespace Gears
{
  template <typename SmartPtr>
  PtrHolder<SmartPtr>::PtrHolder(std::nullptr_t) /*throw (Gears::Exception)*/
    : ptr_(0)
  {}

  template <typename SmartPtr>
  template <typename Other>
  PtrHolder<SmartPtr>::PtrHolder(Other&& sptr) /*throw (Gears::Exception)*/
    : ptr_(sptr)
  {}

  template <typename SmartPtr>
  PtrHolder<SmartPtr>::~PtrHolder() noexcept
  {}

  template <typename SmartPtr>
  template <typename Other>
  PtrHolder<SmartPtr>&
  PtrHolder<SmartPtr>::operator =(Other&& sptr) /*throw (Gears::Exception)*/
  {
    SmartPtr old_ptr;

    {
      Gears::SpinLock::WriteGuard lock(mutex_);
      old_ptr = ptr_;
      ptr_ = sptr;
    }

    return *this;
  }

  template <typename SmartPtr>
  SmartPtr
  PtrHolder<SmartPtr>::get() /*throw (Gears::Exception)*/
  {
    Gears::SpinLock::ReadGuard lock(mutex_);
    return ptr_;
  }

  template <typename SmartPtr>
  const SmartPtr
  PtrHolder<SmartPtr>::get() const /*throw (Gears::Exception)*/
  {
    Gears::SpinLock::ReadGuard lock(mutex_);
    return ptr_;
  }
}

#endif
