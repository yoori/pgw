#ifndef GEARS_HASHTABLEADAPTERS_HPP_
#define GEARS_HASHTABLEADAPTERS_HPP_

#include <gears/SubString.hpp>
#include <gears/Hash.hpp>

/*
 * XXX!
 * StringHashAdapter and SubStringHashAdapter must return equal hash
 * values for equal strings.
 * XXX!
 */

namespace Gears
{
  class StringHashAdapter
  {
  public:
    typedef std::string text_type;

  public:
    StringHashAdapter(const char* text = 0) /*throw (Gears::Exception)*/;
    StringHashAdapter(const Gears::SubString& text) /*throw (Gears::Exception)*/;
    StringHashAdapter(const std::string& text) /*throw (Gears::Exception)*/;
    StringHashAdapter(size_t hash, const char* text)
      /*throw (Gears::Exception)*/;

    StringHashAdapter(const char* buffer, size_t buffer_len)
      /*throw (Gears::Exception)*/;

    StringHashAdapter(StringHashAdapter&&) noexcept;

    StringHashAdapter&
    operator=(const StringHashAdapter&) noexcept;

    StringHashAdapter&
    operator=(StringHashAdapter&&) noexcept;

    StringHashAdapter&
    assign(size_t hash, const char* text)
      /*throw (Gears::Exception)*/;

    StringHashAdapter&
    assign(const char* text) /*throw (Gears::Exception)*/;

    bool
    operator ==(const StringHashAdapter& src) const /*throw (Gears::Exception)*/;
    bool
    operator <(const StringHashAdapter& src) const /*throw (Gears::Exception)*/;
    bool
    operator >(const StringHashAdapter& src) const /*throw (Gears::Exception)*/;

    size_t
    hash() const noexcept;

    /**
     * @return The string on which was calculated hash
     */
    const std::string&
    text() const noexcept;
    operator const std::string&() const noexcept;

  protected:
    void
    hash_i() /*throw (Gears::Exception)*/;

  protected:
    std::string text_;
    size_t hash_;
  };

  class SubStringHashAdapter
  {
  public:
    typedef Gears::SubString text_type;

  public:
    SubStringHashAdapter(const Gears::SubString& text =
      Gears::SubString())
      noexcept;

    template <typename Traits, typename Alloc>
    SubStringHashAdapter(const std::basic_string<char, Traits, Alloc>& text)
      noexcept;

    SubStringHashAdapter(size_t hash, const Gears::SubString& text)
      noexcept;

    bool
    operator ==(const SubStringHashAdapter& src) const
      noexcept;

    bool
    operator <(const SubStringHashAdapter& src) const
      noexcept;

    size_t
    hash() const
      noexcept;

    operator Gears::SubString() const
      noexcept;

    const Gears::SubString&
    text() const noexcept;

  protected:
    void
    calc_hash_()
      noexcept;

  protected:
    Gears::SubString text_;
    size_t hash_;
  };

  template <class T>
  class NumericHashAdapter
  {
  public:
    NumericHashAdapter() /*throw (Gears::Exception)*/;
    NumericHashAdapter(const T& value) /*throw (Gears::Exception)*/;

    bool
    operator ==(const NumericHashAdapter& src) const /*throw (Gears::Exception)*/;
    bool
    operator <(const NumericHashAdapter& src) const /*throw (Gears::Exception)*/;
    bool
    operator >(const NumericHashAdapter& src) const /*throw (Gears::Exception)*/;

    size_t
    hash() const noexcept;

    const T&
    value() const /*throw (Gears::Exception)*/;

  protected:
    T value_;
  };
}

// Inlines

namespace Gears
{
  //
  // StringHashAdapter class
  //
  inline
  StringHashAdapter::StringHashAdapter(const char* text)
    /*throw (Gears::Exception)*/
    : text_(text ? text : "")
  {
    hash_i();
  }

  inline
  StringHashAdapter::StringHashAdapter(StringHashAdapter&& init) noexcept
    : text_(std::move(init.text_)),
      hash_(init.hash_)
  {}
  
  inline
  StringHashAdapter::StringHashAdapter(const Gears::SubString& text)
    /*throw (Gears::Exception)*/
    : text_(text.str())
  {
    hash_i();
  }

  inline
  StringHashAdapter::StringHashAdapter(const std::string& text)
    /*throw (Gears::Exception)*/
    : text_(text)
  {
    hash_i();
  }

  inline
  StringHashAdapter::StringHashAdapter(size_t hash, const char* text)
    /*throw (Gears::Exception)*/
    : text_(text), hash_(hash)
  {
  }

  inline
  StringHashAdapter::StringHashAdapter(const char* buffer, size_t buffer_len)
    /*throw (Gears::Exception)*/
    : text_(buffer, buffer_len)
  {
    hash_i();
  }

  inline
  StringHashAdapter&
  StringHashAdapter::operator=(const StringHashAdapter& init) noexcept
  {
    text_ = init.text_;
    hash_ = init.hash_;
    return *this;
  }

  inline
  StringHashAdapter&
  StringHashAdapter::operator=(StringHashAdapter&& init) noexcept
  {
    text_.swap(init.text_);
    hash_ = init.hash_;
    return *this;
  }

  inline
  StringHashAdapter&
  StringHashAdapter::assign(size_t hash, const char* text)
    /*throw (Gears::Exception)*/
  {
    text_.assign(text);
    hash_ = hash;
    return *this;
  }

  inline
  StringHashAdapter&
  StringHashAdapter::assign(const char* text) /*throw (Gears::Exception)*/
  {
    text_.assign(text);
    hash_i();

    return *this;
  }

  inline
  bool
  StringHashAdapter::operator ==(const StringHashAdapter& src) const
    /*throw (Gears::Exception)*/
  {
    return text_ == src.text_;
  }

  inline
  bool
  StringHashAdapter::operator <(const StringHashAdapter& src)
    const /*throw (Gears::Exception)*/
  {
    return text_ < src.text_;
  }

  inline
  bool
  StringHashAdapter::operator >(const StringHashAdapter& src)
    const /*throw (Gears::Exception)*/
  {
    return text_ > src.text_;
  }

  inline
  size_t
  StringHashAdapter::hash() const noexcept
  {
    return hash_;
  }

  inline
  void
  StringHashAdapter::hash_i() /*throw (Gears::Exception)*/
  {
    Murmur64Hash hash(hash_);
    hash_add(hash, text_);
  }

  inline
  const std::string&
  StringHashAdapter::text() const noexcept
  {
    return text_;
  }

  inline
  StringHashAdapter::operator const std::string&() const
    noexcept
  {
    return text_;
  }

//
// SubStringHashAdapter class
//
  inline
  SubStringHashAdapter::SubStringHashAdapter(const Gears::SubString& text)
    noexcept
    : text_(text)
  {
    calc_hash_();
  }

  template <typename Traits, typename Alloc>
  SubStringHashAdapter::SubStringHashAdapter(
    const std::basic_string<char, Traits, Alloc>& text) noexcept
    : text_(text)
  {
    calc_hash_();
  }

  inline
  SubStringHashAdapter::SubStringHashAdapter(size_t hash,
    const Gears::SubString& text)
    noexcept
    : text_(text), hash_(hash)
  {
  }

  inline
  bool
  SubStringHashAdapter::operator ==(const SubStringHashAdapter& src) const
    noexcept
  {
    return text_ == src.text_;
  }

  inline
  bool
  SubStringHashAdapter::operator <(const SubStringHashAdapter& src) const
    noexcept
  {
    return text_ < src.text_;
  }

  inline
  size_t
  SubStringHashAdapter::hash() const noexcept
  {
    return hash_;
  }

  inline
  SubStringHashAdapter::operator Gears::SubString() const noexcept
  {
    return text_;
  }

  inline
  const Gears::SubString&
  SubStringHashAdapter::text() const noexcept
  {
    return text_;
  }

  inline
  void
  SubStringHashAdapter::calc_hash_() noexcept
  {
    Murmur64Hash hash(hash_);
    hash_add(hash, text_);
  }

//
// NumericHashAdapter template
//
  template <class T>
  NumericHashAdapter<T>::NumericHashAdapter() /*throw (Gears::Exception)*/
    : value_(0)
  {
  }

  template <class T>
  NumericHashAdapter<T>::NumericHashAdapter(const T& value)
    /*throw (Gears::Exception)*/
    : value_(value)
  {
  }

  template <class T>
  bool
  NumericHashAdapter<T>::operator ==(const NumericHashAdapter& src) const
    /*throw (Gears::Exception)*/
  {
    return value_ == src.value_;
  }

  template <class T>
  bool
  NumericHashAdapter<T>::operator <(const NumericHashAdapter& src) const
    /*throw (Gears::Exception)*/
  {
    return value_ < src.value_;
  }

  template <class T>
  bool
  NumericHashAdapter<T>::operator >(const NumericHashAdapter& src) const
    /*throw (Gears::Exception)*/
  {
    return value_ > src.value_;
  }

  template <class T>
  size_t
  NumericHashAdapter<T>::hash() const noexcept
  {
    return static_cast<size_t>(value_);
  }

  template <class T>
  const T&
  NumericHashAdapter<T>::value() const /*throw (Gears::Exception)*/
  {
    return value_;
  }

  inline
  std::ostream&
  operator <<(std::ostream& ostr, const StringHashAdapter& str)
    /*throw (Gears::Exception)*/
  {
    ostr << str.text();
    return ostr;
  }

  inline
  std::istream&
  operator >>(std::istream& istr, StringHashAdapter& str)
    /*throw (Gears::Exception)*/
  {
    std::string str_;
    istr >> str_;
    str = StringHashAdapter(str_);
    return istr;
  }
}

#endif
