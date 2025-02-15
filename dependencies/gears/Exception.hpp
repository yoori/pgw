#ifndef BASIC_EXCEPTION_HPP
#define BASIC_EXCEPTION_HPP

#include <stdexcept>
#include <string>

#include <string.h>
#include <stdlib.h>

#define DECLARE_EXCEPTION(NAME, BASE)           \
  class NAME##_tag_; \
  typedef Gears::CompositeException<NAME##_tag_, BASE> NAME

namespace Gears
{
  template<typename CharType, typename Traits, typename Checker>
  class BasicSubString;

  /** The standard library exception. */
  typedef std::exception Exception;

  /**
   * A descriptive exception.
   * Extends std::exception to provides textual information describing
   * the exception raised.
   */
  class DescriptiveException : public virtual Exception
  {
  protected:
    explicit
    DescriptiveException(const char* description)
      noexcept;

    DescriptiveException(const char* description, size_t length)
      noexcept;

    explicit
    DescriptiveException(const std::string& description)
      noexcept;

    DescriptiveException(const DescriptiveException& exception)
      noexcept;

    template<typename CharType, typename Traits, typename Checker>
    DescriptiveException(
      const BasicSubString<CharType, Traits, Checker>& description)
      noexcept;

    DescriptiveException&
    operator=(const DescriptiveException& exception) noexcept;

  public:
    virtual ~DescriptiveException() noexcept;

    /** Returns the message associated with the exception. */
    virtual const char* what() const noexcept;

  protected:
    DescriptiveException() noexcept;

    void
    copy_string_(const char* src, char* dst, size_t size) noexcept;

    void
    init_(const char* description) noexcept;

    void
    init_(const char* description, size_t length)
      noexcept;

  protected:
    enum { DESC_EXCEPTION_BUFFER_SIZE = 10 * 1024 };
    char description_[DESC_EXCEPTION_BUFFER_SIZE];
  };

  template <typename Tag, typename Base>
  class CompositeException: public virtual Base
  {
  public:
    explicit
    CompositeException(const char* description) noexcept;

    CompositeException(const char* description, size_t length) noexcept;

    explicit
    CompositeException(const std::string& description)
      noexcept;

    template<typename CharType, typename Traits, typename Checker>
    CompositeException(
      const BasicSubString<CharType, Traits, Checker>& description)
      noexcept;

  protected:
    CompositeException() noexcept;
  };
}

namespace Gears
{
  /* DescriptiveException */
  inline
  DescriptiveException::DescriptiveException()
    noexcept
  {
    init_(0, 0);
  }

  inline
  DescriptiveException::DescriptiveException(
    const char* description)
    noexcept
  {
    init_(description, ::strlen(description));
  }

  inline
  DescriptiveException::DescriptiveException(
    const char* description,
    size_t length)
    noexcept
  {
    init_(description, length);
  }

  inline
  DescriptiveException::DescriptiveException(
    const std::string& description)
    noexcept
  {
    init_(description.data(), description.size());
  }

  inline
  DescriptiveException::~DescriptiveException()
    noexcept
  {
    memset(description_, 0, sizeof(description_));
  }

  inline
  DescriptiveException::DescriptiveException(
    const DescriptiveException& exception) noexcept
    : Exception()
  {
    init_(exception.description_);
  }

  template<typename CharType, typename Traits, typename Checker>
  DescriptiveException::DescriptiveException(
    const BasicSubString<CharType, Traits, Checker>& description)
    noexcept
  {
    init_(description.data(), description.size());
  }

  inline
  DescriptiveException&
  DescriptiveException::operator=(
    const DescriptiveException& exception)
    noexcept
  {
    init_(exception.description_);
    return *this;
  }

  inline
  const char*
  DescriptiveException::what() const noexcept
  {
    return description_;
  }

  inline
  void
  DescriptiveException::copy_string_(const char* src, char* dst, size_t size)
    noexcept
  {
    if(src)
    {
      char* end = dst + size - 1;
      while ((*dst++ = *src++) && dst < end) {}
      *end = '\0';
    }
    else
    {
      *dst = '\0';
    }
  }

  inline
  void
  DescriptiveException::init_(const char* description)
    noexcept
  {
    copy_string_(description, description_, DESC_EXCEPTION_BUFFER_SIZE);
  }

  inline
  void
  DescriptiveException::init_(const char* description, size_t size)
    noexcept
  {
    if(size)
    {
      if(size > DESC_EXCEPTION_BUFFER_SIZE - 1)
      {
        size = DESC_EXCEPTION_BUFFER_SIZE - 1;
      }
      ::memcpy(description_, description, size);
    }

    description_[size] = '\0';
  }

  /* Composite */

  template<typename TagType, typename BaseType>
  CompositeException<TagType, BaseType>::CompositeException() noexcept
  {}

  template<typename TagType, typename BaseType>
  CompositeException<TagType, BaseType>::CompositeException(
    const char* description)
    noexcept
  {
    BaseType::init_(description);
  }

  template<typename TagType, typename BaseType>
  CompositeException<TagType, BaseType>::CompositeException(
    const char* description, size_t size)
    noexcept
  {
    BaseType::init_(description, size);
  }

  template<typename TagType, typename BaseType>
  CompositeException<TagType, BaseType>::CompositeException(
    const std::string& description)
    noexcept
  {
    BaseType::init_(description.data(), description.size());
  }

  template<typename TagType, typename BaseType>
  template<typename CharType, typename Traits, typename Checker>
  CompositeException<TagType, BaseType>::CompositeException(
    const BasicSubString<CharType, Traits, Checker>& description)
    noexcept
  {
    BaseType::init_(description.data(), description.size());
  }
}

#endif /*BASIC_EXCEPTION_HPP*/
