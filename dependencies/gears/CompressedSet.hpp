#ifndef GEARS_COMPRESSEDSET_HPP_
#define GEARS_COMPRESSEDSET_HPP_

#include <map>

#include <gears/Exception.hpp>
#include <gears/TypeTraits.hpp>

namespace Gears
{
  /**
   * Implementation of Interval tree. For every interval [low, high]
   * (low <= high) the corresponding [first, second] element is stored
   * in the map
   * For two sequential elements [first1, second1] and [first2, second2]
   * second1 + 1 < first2 is always true
   *
   * Implementation is not thread safe
   */
  template <typename Integer>
  class CompressedSet
  {
  public:
    /**
     * Constructor
     */
    CompressedSet() /*throw (Gears::Exception)*/;

    /**
     * Checks if the set is empty
     * @return true if no element is present in the set
     */
    bool
    empty() const noexcept;

    /**
     * Adds interval [low, high] to the set. Merges stored intervals
     * if required
     * @param low low bound of the interval
     * @param high high bound of the interval
     */
    void
    add(Integer low, Integer high) /*throw (Gears::Exception)*/;

    /**
     * Adds interval [value, value] to the set. Merges stored intervals
     * if required
     * @param value value to insert
     */
    void
    add(Integer value) /*throw (Gears::Exception)*/;

    /**
     * Adds all intervals from cset to the set. Merges stored intervals
     * if required
     * @param cset set of intervals to insert
     */
    void
    add(const CompressedSet<Integer>& cset) /*throw (Gears::Exception)*/;

    /**
     * Removes interval [low, high] from the set. Splits stored intervals
     * if required
     * @param low low bound of the interval
     * @param high high bound of the interval
     */
    void
    remove(Integer low, Integer high) /*throw (Gears::Exception)*/;

    /**
     * Removes interval [value, value] from the set. Splits stored intervals
     * if required
     * @param value value to remove
     */
    void
    remove(Integer value) /*throw (Gears::Exception)*/;

    /**
     * Removes all intervals from cset from the set. Splits stored intervals
     * if required
     * @param cset set of intervals to remove
     */
    void
    remove(const CompressedSet<Integer>& cset) /*throw (Gears::Exception)*/;

    /**
     * Clears the entire set
     */
    void
    clear() /*throw (Gears::Exception)*/;

    /**
     * Checks if value belongs to any interval stored in the map
     * @param value value to check
     * @return if value belongs to the set
     */
    bool
    belongs(Integer value) const /*throw (Gears::Exception)*/;


    enum CheckStatus
    {
      CS_NONE, // None is present
      CS_ALL, // All are present
      CS_SOME // Some are present, some are not
    };

    /**
     * Checks if every value in interval [low, high] is present in the set
     * @param low low bound of the interval
     * @param high high bound of the interval
     * @return status of presence of every value of interval in the set
     */
    CheckStatus
    check_presence(Integer low, Integer high) const /*throw (Gears::Exception)*/;

  protected:
    typedef std::map<Integer, Integer> Holder;

    Holder holder_;
    mutable typename Holder::const_iterator last_found_;
  };
}

//
// Implementation
//

namespace Gears
{
  template <typename Integer>
  CompressedSet<Integer>::CompressedSet() /*throw (Gears::Exception)*/
    : last_found_(holder_.end())
  {}

  template <typename Integer>
  bool
  CompressedSet<Integer>::empty() const noexcept
  {
    return holder_.empty();
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::add(Integer low, Integer high)
    /*throw (Gears::Exception)*/
  {
    if (low > high)
    {
      return;
    }

    last_found_ = holder_.end();

    // Finding start element max(itor->first) <= low
    typename Holder::iterator itor(holder_.lower_bound(low));
    if ((itor == holder_.end() || itor->first != low) &&
      itor != holder_.begin())
    {
      --itor;
    }

    // Inserting new element or modifying existing
    if (itor == holder_.end() || itor->first > low ||
      safe_next(itor->second) < low)
    {
      itor = holder_.insert(typename Holder::value_type(low, high)).first;
    }
    else
    {
      if (itor->second < high)
      {
        itor->second = high;
      }
    }

    // Removing overlapped
    typename Holder::iterator base(itor);
    Integer high_next = safe_next(high);
    for (++itor; itor != holder_.end() && itor->first <= high_next;)
    {
      if (itor->second > high)
      {
        base->second = itor->second;
        holder_.erase(itor);
        break;
      }

      holder_.erase(itor++);
    }
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::add(Integer value) /*throw (Gears::Exception)*/
  {
    add(value, value);
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::add(const CompressedSet<Integer>& cset)
    /*throw (Gears::Exception)*/
  {
    if (this == &cset)
    {
      return;
    }

    for (typename Holder::const_iterator itor(cset.holder_.begin());
      itor != cset.holder_.end(); ++itor)
    {
      add(itor->first, itor->second);
    }
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::remove(Integer low, Integer high)
    /*throw (Gears::Exception)*/
  {
    if (low > high)
    {
      return;
    }

    last_found_ = holder_.end();

    // Finding start element max(itor->first) <= low
    typename Holder::iterator itor(holder_.lower_bound(low));
    if ((itor == holder_.end() || itor->first != low) &&
      itor != holder_.begin())
    {
      --itor;
    }

    Integer high_next = safe_next(high);
    while (itor != holder_.end() && itor->first < high_next)
    {
      if (itor->first >= low)
      {
        if (itor->second <= high)
        {
          holder_.erase(itor++);
          continue;
        }

        // itor->first >= low && itor->second > high
        holder_.insert(typename Holder::value_type(high_next, itor->second));
        holder_.erase(itor);
        break;
      }

      // itor->first < low
      if (itor->second < low)
      {
        ++itor;
        continue;
      }

      // itor->first < low && itor->second >= low
      if (itor->second <= high)
      {
        itor->second = low - 1; // low - 1 >= itor->first
        continue;
      }

      // itor->first < low && itor->second > high
      holder_.insert(typename Holder::value_type(high_next, itor->second));
      itor->second = low - 1; // low - 1 >= itor_first
    }
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::remove(Integer value) /*throw (Gears::Exception)*/
  {
    remove(value, value);
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::remove(const CompressedSet<Integer>& cset)
    /*throw (Gears::Exception)*/
  {
    if (this == &cset)
    {
      return;
    }

    for (typename Holder::const_iterator itor(cset.holder_.begin());
      itor != cset.holder_.end(); ++itor)
    {
      remove(itor->first, itor->second);
    }
  }

  template <typename Integer>
  void
  CompressedSet<Integer>::clear() /*throw (Gears::Exception)*/
  {
    holder_.clear();
    last_found_ = holder_.end();
  }

  template <typename Integer>
  bool
  CompressedSet<Integer>::belongs(Integer value) const /*throw (Gears::Exception)*/
  {
    if (last_found_ != holder_.end() && last_found_->first <= value &&
      last_found_->second >= value)
    {
      return true;
    }

    // first >= value or last_found_ == end
    last_found_ = holder_.lower_bound(value);

    if (last_found_ != holder_.end() && last_found_->first == value)
    {
      return true;
    }

    // true if --itor, itor->first < value <= itor->second
    if (last_found_ == holder_.begin())
    {
      return false;
    }
    --last_found_;
    return value <= last_found_->second;
  }

  template <typename Integer>
  typename CompressedSet<Integer>::CheckStatus
  CompressedSet<Integer>::check_presence(Integer low, Integer high) const
    /*throw (Gears::Exception)*/
  {
    if (low > high)
    {
      return CS_NONE;
    }

    // first >= value or last_found_ == end
    typename Holder::const_iterator itor = holder_.lower_bound(low);

    if (itor != holder_.end())
    {
      if (itor->first == low)
      {
        return itor->second >= high ? CS_ALL : CS_SOME;
      }

      // first > low
      if (itor->first <= high)
      {
        return CS_SOME;
      }
    }

    if (itor == holder_.begin())
    {
      return CS_NONE;
    }

    --itor;

    // itor->first < low
    if (itor->second < low)
    {
      return CS_NONE;
    }

    // first < low && second >= low
    return itor->second >= high ? CS_ALL : CS_SOME;
  }
}

#endif
