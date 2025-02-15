#ifndef GEARS_HASHTABLE_HPP_
#define GEARS_HASHTABLE_HPP_

#include <unordered_set>
#include <unordered_map>
#include <functional>

#include <gears/HashTableAdapters.hpp>

namespace Gears
{  
  template <class Key>
  struct HashFunForHashAdapter
  {
    size_t
    operator()(const Key& value) const /*throw (Gears::Exception)*/;
  };

  template <class Key, class Value,
    class Alloc = std::allocator<std::pair<const Key, Value> >,
    class EqualKey = std::equal_to<Key> >
  class HashTable :
    public std::unordered_map<Key, Value, HashFunForHashAdapter<Key>,
      EqualKey,
      typename Alloc::template rebind<std::pair<const Key, Value> >::other>
  {
  private:
    typedef std::unordered_map<Key, Value, HashFunForHashAdapter<Key>,
      EqualKey,
      typename Alloc::template rebind<std::pair<const Key, Value> >::other>
      Parent;

  public:
    typedef size_t size_type;
    typedef Value data_type;

    HashTable(size_t table_size = 0) /*throw (Gears::Exception)*/;

    size_type
    table_size() const noexcept;

    void
    table_size(const size_t&) noexcept;
    void
    optimize() noexcept;

    bool
    operator ==(const HashTable& table) const noexcept;
  };

  template <class Key, class Alloc = std::allocator<Key>,
    class EqualKey = std::equal_to<Key> >
  class GnuHashSet :
    public std::unordered_set<Key, HashFunForHashAdapter<Key>,
      EqualKey, typename Alloc::template rebind<Key>::other>
  {
  public:
    typedef std::unordered_set<Key, HashFunForHashAdapter<Key>,
      EqualKey, typename Alloc::template rebind<Key>::other>
      Parent;

    typedef Key key_type;
    typedef size_t size_type;

    bool
    operator ==(const GnuHashSet& set) const noexcept;
  };
}

//
// INLINES
//

namespace Gears
{
  //
  // HashFunForHashAdapter class
  //

  template <class Key>
  size_t
  HashFunForHashAdapter<Key>::operator()(const Key& value) const
    /*throw (Gears::Exception)*/
  {
    return static_cast<size_t>(value.hash());
  }

  //
  // HashTable class
  //

  template <class Key, class Value, class Alloc, class EqualKey>
  HashTable<Key, Value, Alloc, EqualKey>::HashTable(size_t table_size)
    /*throw (Gears::Exception)*/
    : Parent(table_size)
  {}

  template <class Key, class Value, class Alloc, class EqualKey>
  typename HashTable<Key, Value, Alloc, EqualKey>::size_type
  HashTable<Key, Value, Alloc, EqualKey>::table_size() const noexcept
  {
    return Parent::size();
  }

  template <class Key, class Value, class Alloc, class EqualKey>
  void
  HashTable<Key, Value, Alloc, EqualKey>::optimize() noexcept
  {
  }

  template <class Key, class Value, class Alloc, class EqualKey>
  void
  HashTable<Key, Value, Alloc, EqualKey>::table_size(
    const size_t& new_size) noexcept
  {
    Parent::resize(new_size);
  }

  template <class Key, class Value, class Alloc, class EqualKey>
  bool
  HashTable<Key, Value, Alloc, EqualKey>::operator ==(
    const HashTable& table) const noexcept
  {
    if (this->size() != table.size())
    {
      return false;
    }
    for (typename Parent::const_iterator itor(this->begin());
      itor != this->end(); ++itor)
    {
      typename Parent::const_iterator found(table.find(itor->first));
      if (found == table.end() || !(itor->second == found->second))
      {
        return false;
      }
    }
    return true;
  }

  //
  // GnuHashSet class
  //

  template <class Key, class Alloc, class EqualKey>
  bool
  GnuHashSet<Key, Alloc, EqualKey>::operator ==(const GnuHashSet& set) const
    noexcept
  {
    if (this->size() != set.size())
    {
      return false;
    }
    for (typename Parent::const_iterator itor(this->begin());
      itor != this->end(); ++itor)
    {
      if (set.find(itor->first) == set.end())
      {
        return false;
      }
    }
    return true;
  }
}

#endif
