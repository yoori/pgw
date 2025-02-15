#ifndef GEARS_SINGLETON_HPP_
#define GEARS_SINGLETON_HPP_

//#define LOUD_COUNTER_BACKTRACE

#include <cstdio>
#include <memory>
#include <cassert>

#include <signal.h>
#include <unistd.h>
#include <atomic>

#include <gears/Lock.hpp>
#include <gears/Uncopyable.hpp>
//#include <gears/Function.hpp>

#ifdef LOUD_COUNTER_BACKTRACE
#include <gears/Proc.hpp>
#endif

#include <gears/OutputMemoryStream.hpp>

namespace Gears
{
  /**
   * All instances of this and descending classes are removed only after
   * exit(3) call or main exit.
   * Useful for singletons.
   */
  class AtExitDestroying : private Uncopyable
  {
  public:
    enum DEFAULT_PRIORITIES
    {
      DP_USUAL_SINGLETON = 0,
      // CorbaClientAdapter::Orbs may be used by usual singletons
      DP_CLIENT_ORBS = 8192,
      // LoudCounters must be destroyed after all
      DP_LOUD_COUNTER = 16384,
    };

  protected:
    /**
     * Constructor
     * Optionally registers destroy function in atexit
     * Inserts object into the list of destroyable objects
     * @param priority objects with lesser value will be destroyed sooner
     */
    explicit
    AtExitDestroying(int priority) noexcept;

    /**
     * Destructor
     */
    virtual
    ~AtExitDestroying() noexcept;

  private:
    /**
     * Destroys the registered objects
     */
    static
    void
    destroy_at_exit_() noexcept;

    static Gears::Mutex mutex_;
    static bool registered_;
    static AtExitDestroying* lower_priority_head_;
    AtExitDestroying* lower_priority_;
    AtExitDestroying* equal_priority_;
    int priority_;
  };

  namespace Helper
  {
    /**
     * Destroys Object on exit
     */
    template <typename Object, typename Pointer, const int PRIORITY>
    class AtExitDestroyer : public AtExitDestroying
    {
    public:
      /**
       * Constructor
       * @param object object to destroy at exit
       */
      explicit
      AtExitDestroyer(Object* object) noexcept;

    protected:
      /**
       * Destructor
       */
      virtual
      ~AtExitDestroyer() noexcept;

    private:
      Pointer object_;
    };

    /**
     * Adapter for std::unique_ptr
     */
    template <typename Type>
    class AutoPtr : public std::unique_ptr<Type>
    {
    public:
      explicit
      AutoPtr(Type* object) noexcept;
      Type*
      in() noexcept;
      Type*
      retn() noexcept;
    };

    /**
     * Adapter for simple pointer
     */
    template <typename Type>
    class SimplePtr
    {
    public:
      explicit
      SimplePtr(Type* object) noexcept;
      Type*
      in() noexcept;
      Type*
      retn() noexcept;

    private:
      Type* ptr_;
    };
  }

  /**
   * Singleton
   * Safe to use in multithreaded environment (even before main() call).
   * Single object is destroyed after exit(3) call or main() exit.
   * It is not safe to call instance() at that time.
   */
  template <typename Single, typename Pointer = Helper::AutoPtr<Single>,
    const int PRIORITY = AtExitDestroying::DP_USUAL_SINGLETON>
  class Singleton
  {
  public:
    /**
     * Optionally creates a new Single object or returns reference to the
     * existing.
     * It is not safe to call it after exit(3) call or main() exit.
     * @return reference to the unique object
     */
    static
    Single&
    instance() /*throw (Gears::Exception)*/;

  protected:
    static Gears::Mutex mutex_;
    static volatile sig_atomic_t initialized_;
    static Single* volatile instance_;
  };

  /**
   * Template class is aimed to allow only one instance of certain type
   * to exist at the given point in time. Lifetime of each of those instances
   * are controlled manually.
   */
  template <typename Determinator,
    typename BaseException = Gears::DescriptiveException>
  class Unique : private Uncopyable
  {
  public:
    DECLARE_EXCEPTION(Exception, BaseException);

  protected:
    /**
     * Constructor
     * Successfully constructs the object only if another one does not exist.
     */
    Unique() /*throw (Gears::Exception, Exception)*/;
    /**
     * Destructor
     * Allows creating of another object of the same type.
     */
    ~Unique() noexcept;

  private:
    static Gears::Mutex mutex_;
    static Unique<Determinator, BaseException>* volatile existing_;
  };

  /**
   * Class informs if some objects of the specified class have not been
   * destroyed on program shutdown.
   */
  template <typename Determinator>
  class AllDestroyer
  {
  protected:
    /**
     * Constructor.
     * Increases the number of objects created.
     */
    AllDestroyer() noexcept;
    /**
     * Constructor.
     * Increases the number of objects created.
     */
    AllDestroyer(const AllDestroyer&) noexcept;
    /**
     * Destructor.
     * Decreases the number of objects created.
     */
    ~AllDestroyer() noexcept;

  private:
    struct Info
    {
#ifdef LOUD_COUNTER_BACKTRACE
      char info[2048];
      Info* next;
#endif
    };
    Info info_;

    class LoudCounter
    {
    public:
      LoudCounter() noexcept;

      void
      increment(Info* info) noexcept;

      void
      decrement(Info* info) noexcept;

      void
      check() noexcept;

    private:
      virtual
      ~LoudCounter() noexcept;

      std::atomic<int> counter_;

#ifdef LOUD_COUNTER_BACKTRACE
      Gears::Mutex mutex_;
      Info* head_;
#endif
    };

    typedef std::shared_ptr<LoudCounter> LoudCounter_var;

    class LoudCounterHolder : private Uncopyable
    {
    public:
      typedef Singleton<LoudCounterHolder,
        Helper::AutoPtr<LoudCounterHolder>,
        AtExitDestroying::DP_LOUD_COUNTER> Single;

      LoudCounterHolder() /*throw (Gears::Exception)*/;

      ~LoudCounterHolder() noexcept;

      LoudCounter_var
      counter() noexcept;

    private:
      LoudCounter_var counter_;
    };

    LoudCounter_var counter_;
  };
}

namespace Gears
{
  //
  // AtExitDestroying class
  //

  inline
  AtExitDestroying::~AtExitDestroying() noexcept
  {}

  namespace Helper
  {
    //
    // AtExitDestroyer class
    //

    template <typename Object, typename Pointer, const int PRIORITY>
    AtExitDestroyer<Object, Pointer, PRIORITY>::AtExitDestroyer(
      Object* object) noexcept
      : AtExitDestroying(PRIORITY), object_(object)
    {}

    template <typename Object, typename Pointer, const int PRIORITY>
    AtExitDestroyer<Object, Pointer, PRIORITY>::~AtExitDestroyer() noexcept
    {}


    //
    // class AutoPtr
    //

    template <typename Type>
    AutoPtr<Type>::AutoPtr(Type* object) noexcept
      : std::unique_ptr<Type>(object)
    {}

    template <typename Type>
    Type*
    AutoPtr<Type>::in() noexcept
    {
      return this->get();
    }

    template <typename Type>
    Type*
    AutoPtr<Type>::retn() noexcept
    {
      return this->release();
    }

    //
    // class SimplePtr
    //

    template <typename Type>
    SimplePtr<Type>::SimplePtr(Type* object) noexcept
      : ptr_(object)
    {}

    template <typename Type>
    Type*
    SimplePtr<Type>::in() noexcept
    {
      return ptr_;
    }

    template <typename Type>
    Type*
    SimplePtr<Type>::retn() noexcept
    {
      Type* ptr(ptr_);
      ptr_ = 0;
      return ptr;
    }
  }

  //
  // Singleton class
  //

  // All of these are initialized statically
  template <typename Single, typename Pointer, const int PRIORITY>
  Gears::Mutex Singleton<Single, Pointer, PRIORITY>::mutex_;

  template <typename Single, typename Pointer, const int PRIORITY>
  volatile sig_atomic_t Singleton<Single, Pointer, PRIORITY>::initialized_ =
    false;

  template <typename Single, typename Pointer, const int PRIORITY>
  Single* volatile Singleton<Single, Pointer, PRIORITY>::instance_ = 0;

  template <typename Single, typename Pointer, const int PRIORITY>
  Single&
  Singleton<Single, Pointer, PRIORITY>::instance() /*throw (Gears::Exception)*/
  {
    if (!initialized_)
    {
      {
        Gears::Mutex::WriteGuard guard(mutex_);
        if (!instance_)
        {
          Pointer single(new Single);
          new Helper::AtExitDestroyer<Single, Pointer, PRIORITY>(single.in());
          instance_ = single.retn();
        }
      }
      initialized_ = true;
    }
    return *instance_;
  }


  //
  // Unique class
  //

  template <typename Determinator, typename BaseException>
  Gears::Mutex Unique<Determinator, BaseException>::mutex_;

  template <typename Determinator, typename BaseException>
  Unique<Determinator, BaseException>*
    volatile Unique<Determinator, BaseException>::existing_ = 0;

  template <typename Determinator, typename BaseException>
  Unique<Determinator, BaseException>::Unique()
    /*throw (Gears::Exception, Exception)*/
  {
    static const char* FUN = "Unique::Unique()";

    Gears::Mutex::WriteGuard guard(mutex_);

    if (existing_)
    {
      ErrorStream ostr;
      ostr << FUN << ": another unique " << existing_ << " still exists";
      throw Exception(ostr.str());
    }

    existing_ = this;
  }

  template <typename Determinator, typename BaseException>
  Unique<Determinator, BaseException>::~Unique() noexcept
  {
    Gears::Mutex::WriteGuard guard(mutex_);
    assert(existing_ == this);
    existing_ = 0;
  }

  //
  // AllDestroyer::LoudCounter class
  //

  template <typename Determinator>
  AllDestroyer<Determinator>::LoudCounter::LoudCounter() noexcept
    : counter_(0)
#ifdef LOUD_COUNTER_BACKTRACE
      ,
      head_(0)
#endif
  {}

  template <typename Determinator>
  AllDestroyer<Determinator>::LoudCounter::~LoudCounter() noexcept
  {}

  template <typename Determinator>
  void
  AllDestroyer<Determinator>::LoudCounter::increment(Info* info) noexcept
  {
    ++counter_;

#ifdef LOUD_COUNTER_BACKTRACE
    *info->info = '\0';
    Proc::backtrace(info->info, sizeof(info->info), 4, 10);
    Gears::Mutex::WriteGuard guard(mutex_);
    info->next = head_;
    head_ = info;
#else
    (void)info;
#endif
  }

  template <typename Determinator>
  void
  AllDestroyer<Determinator>::LoudCounter::decrement(Info* info) noexcept
  {
    --counter_;

#ifdef LOUD_COUNTER_BACKTRACE
    Gears::Mutex::WriteGuard guard(mutex_);
    for (Info** p = &head_; *p; p = &(*p)->next)
    {
      if (*p == info)
      {
        *p = (*p)->next;
        break;
      }
    }
#else
    (void)info;
#endif
  }

  template <typename Determinator>
  void
  AllDestroyer<Determinator>::LoudCounter::check() noexcept
  {
    int counter = static_cast<int>(counter_);
    if (counter)
    {
      char buf[8192];
      int len = std::snprintf(buf, sizeof(buf),
        "Not been removed %i of %s\n", counter,
        Determinator::PRINTABLE_NAME);
#ifdef LOUD_COUNTER_BACKTRACE
      {
        Gears::Mutex::WriteGuard guard(mutex_);
        for (Info* p = head_; p; p = p->next)
        {
          if (len == sizeof(buf))
          {
            break;
          }

          int s = std::min(strlen(p->info), sizeof(buf) - len - 1);
          memcpy(buf + len, p->info, s);
          buf[len + s] = '\n';
          len += s + 1;
        }
      }
#endif
      write(STDERR_FILENO, buf, len);
    }
  }

  //
  // AllDestroyer::LoudCounterHolder class
  //

  template <typename Determinator>
  AllDestroyer<Determinator>::LoudCounterHolder::LoudCounterHolder()
    /*throw (Gears::Exception)*/
    : counter_(new LoudCounter)
  {}

  template <typename Determinator>
  AllDestroyer<Determinator>::LoudCounterHolder::~LoudCounterHolder() noexcept
  {
    counter_->check();
  }

  template <typename Determinator>
  typename AllDestroyer<Determinator>::LoudCounter_var
  AllDestroyer<Determinator>::LoudCounterHolder::counter() noexcept
  {
    return counter_;
  }

  //
  // AllDestroyer class
  //

  template <typename Determinator>
  AllDestroyer<Determinator>::AllDestroyer() noexcept
    : counter_(
        AllDestroyer<Determinator>::LoudCounterHolder::Single::
          instance().counter())
  {
    counter_->increment(&info_);
  }

  template <typename Determinator>
  AllDestroyer<Determinator>::AllDestroyer(const AllDestroyer& another)
    noexcept
    : counter_(another.counter_)
  {
    counter_->increment(&info_);
  }

  template <typename Determinator>
  AllDestroyer<Determinator>::~AllDestroyer() noexcept
  {
    counter_->decrement(&info_);
  }
}

#endif
