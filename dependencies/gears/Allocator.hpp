#ifndef GEARS_ALLOCATOR_HPP
#define GEARS_ALLOCATOR_HPP

#include <signal.h>
#include <memory>
#include <iostream>

#include <gears/Exception.hpp>
#include <gears/Lock.hpp>

namespace Gears
{
  namespace Allocator
  {
    class Base;
    typedef std::shared_ptr<Base> Base_var;

    /**
     * Base class for all allocators objects, that realize some
     * allocation strategy.
     */
    struct Base
    {
      /**
       * Exception means free memory exhausted.
       */
      DECLARE_EXCEPTION(OutOfMemory, Gears::DescriptiveException);

      typedef void* Pointer;
      typedef const void* ConstPointer;

      /**
       * destructor
       */
      virtual
      ~Base() noexcept = 0;
      
      /**
       * @param size mean request for size bytes for code needs,
       * but allocator can give >= size value bytes.
       * Really allocated value return to client by set size
       * in this case.
       * @return pointer to begin allocated memory, size available
       * for using returns in size.
       */
      virtual
      Pointer
      allocate(size_t& size) /*throw (Gears::Exception, OutOfMemory)*/ = 0;

      /**
       * All size T objects in the area pointed
       * by
       * @param ptr shall be destroyed prior to
       * this call.
       * @param size shall match the
       * value passed to allocate to
       * obtain this memory. Does not
       * throw exceptions. [Note: p shall not be null.]
       */
      virtual
      void
      deallocate(Pointer ptr, size_t size) noexcept = 0;

      /**
       * Approximated cached memory size.
       * @return cached memory size.
       */
      virtual
      size_t
      cached() const /*throw (Gears::Exception)*/;

      /**
       * Print detailed approximate cached memory information.
       */
      virtual
      void
      print_cached(std::ostream& ostr) const /*throw (Gears::Exception)*/;

      /**
       * @return application level default allocator. Usually
       * simple new/delete behavior.
       */
      static
      std::shared_ptr<Base>
      get_default_allocator() /*throw (Gears::Exception)*/;

    protected:
      /**
       * Align number to 2^mask number
       * @param number is number to align
       * @param mask power of 2 to be aligned.
       */ 
      static
      void
      align_(size_t& number, size_t mask) noexcept;
    
    private:
      /// Application level default allocator object.
      static Gears::Mutex default_allocator_creation_mutex_;
      static volatile sig_atomic_t default_allocator_initialized_;
      static std::shared_ptr<Base> default_allocator_;
    };

    class Default: public Base
    {
    public:
      /// default power of 2 for alignment value.
      static const size_t DEF_ALIGN = 10;

      explicit
      Default(size_t align_code = DEF_ALIGN) noexcept;

      /**
       * Destructor
       */
      virtual
      ~Default() noexcept;

      /**
       * Align request size bytes according to MASK_
       * and allocate memory.
       * @param size at minimum memory to be allocated.
       * @return pointer to allocated memory block
       */
      virtual
      Pointer
      allocate(size_t& size) /*throw (Gears::Exception, OutOfMemory)*/;

      /**
       * Deallocate 
       * @param ptr pointer to releasing memory block.
       * @param size not used in this allocator.
       */
      virtual
      void
      deallocate(Pointer ptr, size_t size) noexcept;

    private:
      const size_t MASK_;
    };
  }

  template<
    typename Elem,
    const size_t SIZE,
    typename Buffer,
    typename BufferInitializer = Buffer>
  class BasicFixedBufferAllocator : public std::allocator<Elem>
  {
  public:
    typedef std::allocator<Elem> Allocator;

    /**
     * Constructor without parameters
     */
    BasicFixedBufferAllocator() noexcept;

    /**
     * Constructor with buffer_ init value
     * @param buffer_initializer initializer for buffer_
     */
    BasicFixedBufferAllocator(BufferInitializer buffer_initializer) noexcept;

    /**
     * Allocation function
     * Allows to allocate SIZE bytes one time in a row
     * @param size should be equal to SIZE
     * @return pointer to size_ternal buffer
     */
    typename Allocator::pointer
    allocate(typename Allocator::size_type size, const void* = 0)
      noexcept;

    /**
     * Deallocation function
     * Deallocates previously allocated memory
     * @param ptr should be equal to the pointer returned by allocate()
     * @param size should be equal to SIZE
     */
    void
    deallocate(typename Allocator::pointer ptr,
      typename Allocator::size_type size) noexcept;

  private:
    Buffer buffer_;
    bool allocated_;
  };

  /**
   * Simple buffer allocator
   * Allows a single allocation on preallocated buffer
   */
  template <typename Elem, const size_t SIZE>
  class FixedBufferAllocator :
    public BasicFixedBufferAllocator<Elem, SIZE, Elem*>
  {
  public:
    /**
     * Constructor
     * @param buffer preallocated buffer of size not less than SIZE
     */
    FixedBufferAllocator(Elem* buffer) noexcept;
  };

  template <typename Elem, const size_t SIZE, typename Initializer>
  class ArrayBuffer
  {
  public:
    ArrayBuffer(Initializer initializer = Initializer()) noexcept;

    operator Elem*() noexcept;

  private:
    Elem buffer_[SIZE];
  };

  /**
   * Simple stack allocator
   * Required for disuse of heap for OutputStream
   */
  template <typename Elem, const size_t SIZE>
  class StackAllocator :
    public BasicFixedBufferAllocator<
      Elem, SIZE, ArrayBuffer<Elem, SIZE, size_t>, size_t>
  {
  public:
    /**
     * Constructor
     */
    StackAllocator(size_t allocator_initializer) noexcept;
  };
} /*Gears*/

#include "Allocator.tpp"

#endif /*GEARS_ALLOCATOR_HPP*/
