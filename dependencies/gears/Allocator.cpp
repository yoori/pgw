#include <assert.h>
#include <gears/Allocator.hpp>

namespace Gears
{
  namespace Allocator
  {
    Gears::Mutex Base::default_allocator_creation_mutex_;
    volatile sig_atomic_t Base::default_allocator_initialized_;
    Base_var Base::default_allocator_;

    Base_var
    Base::get_default_allocator() /*throw (Gears::Exception)*/
    {
      if (!default_allocator_initialized_)
      {
        {
          Gears::Mutex::WriteGuard guard(default_allocator_creation_mutex_);
          if (!default_allocator_.get())
          {
            default_allocator_.reset(new Default);
          }
        }
        default_allocator_initialized_ = true;
      }

      return default_allocator_;
    }

    Base::~Base() noexcept
    {}

    inline
    void
    Base::align_(size_t& number, size_t mask) noexcept
    {
      number += (-number) & mask;
    }

    size_t
    Base::cached() const /*throw (Gears::Exception)*/
    {
      return 0;
    }

    void
    Base::print_cached(std::ostream& ostr) const /*throw (Gears::Exception)*/
    {
      ostr << '0';
    }

    //
    // class Default
    //

    const size_t Default::DEF_ALIGN;

    Default::Default(size_t align_code) noexcept
      : MASK_((1 << align_code) - 1)
    {}

    Default::~Default() noexcept
    {}

    Base::Pointer
    Default::allocate(size_t& size)
      /*throw (Gears::Exception, OutOfMemory)*/
    {
      align_(size, MASK_);
      return new unsigned char[size];
    }

    void
    Default::deallocate(Pointer ptr, size_t size) noexcept
    {
      (void)size;
      assert(!(size & MASK_));
      delete [] static_cast<unsigned char*>(ptr);
    }
  }
}
