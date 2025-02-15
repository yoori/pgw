#ifndef GEARS_LOCKMAP_HPP_
#define GEARS_LOCKMAP_HPP_

#include <vector>
#include <map>
#include <unordered_map>
#include <memory>

#include <gears/Lock.hpp>

namespace Gears
{
  template<typename KeyType, typename ValueType>
  class Map2Args: public std::map<KeyType, ValueType>
  {};

  template<typename KeyType, typename ValueType>
  class Hash2Args: public std::unordered_map<KeyType, ValueType>
  {};

  template<typename KeyType,
    typename SyncPolicyType = RWLock,
    template<typename, typename> class ContainerType = Map2Args>
  class StrictLockMap
  {
  private:
    typedef Gears::Mutex SyncPolicy;

    class LockHolder
    {
    public:
      friend class LockHolderDeleter;

      LockHolder(StrictLockMap& map_val, const KeyType& key_val) noexcept;

      virtual
      ~LockHolder() noexcept = default;

      StrictLockMap<KeyType, SyncPolicyType, ContainerType>& map;
      KeyType key;
      mutable SyncPolicyType lock;

    protected:
      virtual void
      destroy_() noexcept;
    };

    struct LockHolderDeleter
    {
      void
      operator()(LockHolder* del_obj) noexcept
      {
        del_obj->destroy_();
      }
    };

    typedef std::shared_ptr<LockHolder>
      LockHolder_var;

    template<typename GuardType>
    struct GuardHolder
    {
      GuardHolder(LockHolder_var& lock_holder_val)
        : lock_holder(lock_holder_val),
          guard(lock_holder->lock)
      {}

      LockHolder_var lock_holder;
      GuardType guard;
    };

  public:
    typedef std::shared_ptr<
      GuardHolder<typename SyncPolicyType::ReadGuard> >
      ReadGuard;
    typedef std::shared_ptr<
      GuardHolder<typename SyncPolicyType::WriteGuard> >
      WriteGuard;
    
  public:
    ReadGuard
    read_lock(const KeyType& key) noexcept;

    WriteGuard
    write_lock(const KeyType& key) noexcept;

    typedef ContainerType<KeyType, std::weak_ptr<LockHolder> >
      LockHolderMap;

  protected:
    template<typename GuardType>
    GuardType*
    get_(const KeyType& key) noexcept;

    bool
    close_i_(const KeyType& key) noexcept;
    
  private:
    SyncPolicy map_lock_;
    LockHolderMap map_;
  };

  template<typename KeyType,
    typename SyncPolicyType = RWLock>
  class NoAllocLockMap
  {
  private:
    template<typename GuardType>
    struct GuardHolder
    {
      GuardHolder(SyncPolicyType& lock_val)
        : guard(lock_val)
      {}

      GuardType guard;
    };

  public:
    typedef std::shared_ptr<
      GuardHolder<typename SyncPolicyType::ReadGuard> >
      ReadGuard;
    typedef std::shared_ptr<
      GuardHolder<typename SyncPolicyType::WriteGuard> >
      WriteGuard;

    struct LockWrap: public SyncPolicyType
    {
      LockWrap()
      {}

      LockWrap(const LockWrap&)
        : SyncPolicyType()
      {}

      LockWrap&
      operator=(const LockWrap&)
      {
        return *this;
      }
    };

    typedef std::vector<LockWrap> LockArray;

  public:
    NoAllocLockMap(unsigned long size = 100) noexcept;

    ReadGuard
    read_lock(const KeyType& key) noexcept;

    WriteGuard
    write_lock(const KeyType& key) noexcept;

  protected:
    template<typename GuardType>
    GuardType* get_(const KeyType& key) noexcept
    {
      unsigned long lock_i = key.hash() % locks_.size();
      return new GuardType(locks_[lock_i]);
    }

  private:
    LockArray locks_;
  };

  template<typename KeyType,
    typename SyncPolicyType = RWLock>
  class LockMap: public NoAllocLockMap<KeyType, SyncPolicyType>
  {
  public:
    LockMap(unsigned long size = 100) noexcept
      : NoAllocLockMap<KeyType, SyncPolicyType>(size)
    {}
  };
}

namespace Gears
{
  // StrictStrictLockMap
  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::
  LockHolder::LockHolder(
    StrictLockMap<KeyType, SyncPolicyType, ContainerType>& map_val,
    const KeyType& key_val) noexcept
    : map(map_val), key(key_val)
  {}

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  void
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::
  LockHolder::destroy_() noexcept
  {
    bool to_delete;

    {
      SyncPolicy::WriteGuard guard(map.map_lock_);
      to_delete = map.close_i_(key);
    }

    if(to_delete)
    {
      delete this;
    }
  }

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  typename StrictLockMap<KeyType, SyncPolicyType, ContainerType>::ReadGuard
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::
  read_lock(const KeyType& key)
    noexcept
  {
    return ReadGuard(get_<
      GuardHolder<typename SyncPolicyType::ReadGuard> >(key));
  }

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  typename StrictLockMap<KeyType, SyncPolicyType, ContainerType>::WriteGuard
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::
  write_lock(const KeyType& key)
    noexcept
  {
    return WriteGuard(get_<
      GuardHolder<typename SyncPolicyType::WriteGuard> >(key));
  }

  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  template<typename GuardType>
  GuardType*
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::
  get_(const KeyType& key) noexcept
  {
    LockHolder_var holder;

    {
      SyncPolicy::WriteGuard guard(map_lock_);

      typename LockHolderMap::const_iterator it = map_.find(key);
      if(it != map_.end())
      {
        holder = it->second.lock();
      }

      if(!holder) // holder not found or weak_ptr returned null
      {
        holder.reset(new LockHolder(*this, key), LockHolderDeleter());
        map_[key] = holder;
      }
    }

    return new GuardType(holder);
  }
  template<typename KeyType, typename SyncPolicyType,
    template<typename, typename> class ContainerType>
  bool
  StrictLockMap<KeyType, SyncPolicyType, ContainerType>::
  close_i_(const KeyType& key) noexcept
  {
    auto it = map_.find(key);
    if(it != map_.end() && it->second.ref_count() == 0)
    {
      map_.erase(it);
      return true; // destroy object
    }

    return false;
  }

  // NoAllocLockMap
  template<typename KeyType, typename SyncPolicyType>
  NoAllocLockMap<KeyType, SyncPolicyType>::NoAllocLockMap(
    unsigned long size)
    noexcept
  {
    locks_.resize(size);
  }

  template<typename KeyType, typename SyncPolicyType>
  typename NoAllocLockMap<KeyType, SyncPolicyType>::ReadGuard
  NoAllocLockMap<KeyType, SyncPolicyType>::read_lock(
    const KeyType& key)
    noexcept
  {
    return ReadGuard(get_<
      GuardHolder<typename SyncPolicyType::ReadGuard> >(key));
  }

  template<typename KeyType, typename SyncPolicyType>
  typename NoAllocLockMap<KeyType, SyncPolicyType>::WriteGuard
  NoAllocLockMap<KeyType, SyncPolicyType>::write_lock(
    const KeyType& key)
    noexcept
  {
    return WriteGuard(get_<
      GuardHolder<typename SyncPolicyType::WriteGuard> >(key));
  }
}

#endif /*LOCKMAP_HPP*/
