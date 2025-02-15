#include <gears/MemBuf.hpp>
#include <gears/OutputMemoryStream.hpp>

#if DEV_MEMBUF_BOUNDS > 0
#include <cassert>
#endif


namespace Gears
{
  MemBuf::MemBuf(Allocator::Base_var allocator) noexcept
    : allocator_(
        allocator ? allocator : Allocator::Base::get_default_allocator()),
      ptr_(0), size_(0), capacity_(2 * DEV_MEMBUF_BOUNDS)
  {}

  MemBuf::MemBuf(std::size_t size, Allocator::Base_var allocator)
    /*throw (OutOfMemory)*/
    : allocator_(
        allocator ? allocator : Allocator::Base::get_default_allocator()),
      ptr_(0), size_(0), capacity_(2 * DEV_MEMBUF_BOUNDS)
  {
    try
    {
      alloc(size);
    }
    catch (const Gears::Exception& ex)
    {
      Gears::ErrorStream ostr;
      ostr << "MemBuf::MemBuf(): Can't allocate memory: " << ex.what();
      throw OutOfMemory(ostr.str());
    }
  }

  MemBuf::MemBuf(const MemBuf& right) /*throw (OutOfMemory)*/
    : allocator_(right.allocator_), ptr_(0), size_(0),
      capacity_(2 * DEV_MEMBUF_BOUNDS)
  {
    try
    {
      alloc(right.size());
      memcpy(data(), right.data(), size_);
    }
    catch (const Gears::Exception& ex)
    {
      Gears::ErrorStream ostr;
      ostr << "MemBuf::MemBuf(): Can't allocate memory: " << ex.what();
      throw OutOfMemory(ostr.str());
    }
  }

  MemBuf::MemBuf(const MemBuf& right, Allocator::Base_var allocator)
    /*throw (OutOfMemory)*/
    : allocator_(
        allocator ? allocator : Allocator::Base::get_default_allocator()),
      ptr_(0), size_(0), capacity_(2 * DEV_MEMBUF_BOUNDS)
  {
    try
    {
      alloc(right.size());
      memcpy(data(), right.data(), size_);
    }
    catch (const Gears::Exception& ex)
    {
      Gears::ErrorStream ostr;
      ostr << "MemBuf::MemBuf(): Can't allocate memory: " << ex.what();
      throw OutOfMemory(ostr.str());
    }
  }

  MemBuf::MemBuf(MemBuf&& right) noexcept
    : allocator_(right.allocator_), ptr_(0), size_(0),
      capacity_(2 * DEV_MEMBUF_BOUNDS)
  {
    swap(right);
  }

  MemBuf::MemBuf(const void* ptr, std::size_t size,
    Allocator::Base_var allocator)
    /*throw (RangeError, OutOfMemory)*/
    : allocator_(allocator ? allocator :
        Allocator::Base::get_default_allocator()),
      ptr_(0), size_(0), capacity_(2 * DEV_MEMBUF_BOUNDS)
  {
    try
    {
      alloc(size);
      memcpy(data(), ptr, size_);
    }
    catch (const Gears::Exception& ex)
    {
      Gears::ErrorStream ostr;
      ostr << "MemBuf::MemBuf(): Can't allocate memory: " << ex.what();
      throw OutOfMemory(ostr.str());
    }
  }

  MemBuf::~MemBuf() noexcept
  {
    clear();
  }

  void
  MemBuf::clear() noexcept
  {
    if (capacity())
    {
#if DEV_MEMBUF_BOUNDS > 0
      // check bound constraints
      const unsigned char* ptr = static_cast<const unsigned char*>(ptr_);

      for (size_t i = 0; i < DEV_MEMBUF_BOUNDS; ++i)
      {
        assert(ptr[i] == 0xDD);
      }
      for (size_t i = capacity_ - DEV_MEMBUF_BOUNDS; i < capacity_; ++i)
      {
        assert(ptr[i] == 0xDD);
      }
#endif
      allocator_->deallocate(ptr_, capacity_);
    }
    size_ = 0;
    capacity_ = 2 * DEV_MEMBUF_BOUNDS;
  }

  void
  MemBuf::alloc(std::size_t size) /*throw (Gears::Exception, OutOfMemory)*/
  {
    if (capacity() < size)
    {
      clear();
      try
      {
        std::size_t tmp_capacity = size + 2 * DEV_MEMBUF_BOUNDS;
        ptr_ = allocator_->allocate(tmp_capacity);  // modify tmp_capacity
        capacity_ = tmp_capacity;
      }
      catch (const Gears::Exception& ex)
      {
        Gears::ErrorStream ostr;
        ostr << "MemBuf::alloc(): " << size << ex.what();
        throw OutOfMemory(ostr.str());
      }
#if DEV_MEMBUF_BOUNDS > 0
      memset(ptr_, 0xDD, DEV_MEMBUF_BOUNDS);
      memset(static_cast<unsigned char*>(ptr_) + capacity_ -
        DEV_MEMBUF_BOUNDS, 0xDD, DEV_MEMBUF_BOUNDS);
#endif
    }
    size_ = size;
  }

  void
  MemBuf::resize(std::size_t size) /*throw (RangeError)*/
  {
    if (size > capacity())
    {
      Gears::ErrorStream ostr;
      ostr << "MemBuf::resize(): requested size=" << size << " exceeds capacity=" <<
        capacity();
      throw RangeError(ostr.str());
    }
    size_ = size;
  }

  void
  MemBuf::swap(MemBuf& right) noexcept
  {
    std::swap(ptr_, right.ptr_);
    std::swap(size_, right.size_);
    std::swap(capacity_, right.capacity_);
    std::swap(allocator_, right.allocator_);
  }

  void
  MemBuf::assign(const void* ptr, std::size_t size)
    /*throw (Gears::Exception, OutOfMemory)*/
  {
    alloc(size);
    memcpy(data(), ptr, size);
  }

  MemBuf&
  MemBuf::operator =(MemBuf&& right) noexcept
  {
    if (&right != this)
    {
      swap(right);
    }
    return *this;
  }


  ConstSmartMemBuf_var
  transfer_membuf(const SmartMemBuf_var& ptr)
    /*throw(Gears::Exception)*/
  {
    return ConstSmartMemBuf_var(
      new ConstSmartMemBuf(std::move(ptr->membuf())));
  }
}
