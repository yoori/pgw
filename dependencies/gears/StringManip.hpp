#ifndef GEARS_STRINGMANIP_HPP
#define GEARS_STRINGMANIP_HPP

#include <gears/AsciiStringManip.hpp>
#include <gears/UTF8Category.hpp>
#include <gears/ArrayAutoPtr.hpp>

/**
 * Contain general string manipulation routines
 */
namespace Gears
{
namespace StringManip
{
  DECLARE_EXCEPTION(InvalidFormatException, Gears::DescriptiveException);

  /**
   * The strlcpy() function copy string. It is designed to be safer, more
   * consistent, and less error prone replacements for strncpy(3). Unlike
   * that function, strlcpy() takes the full size of the buffer (not just
   * the length) and guarantees to NUL-terminate the result (as long as size
   * is larger than 0). Note that you should include a byte for the NUL in
   * size. Also note that strlcpy() only operates on true "C" strings.
   * This means that src must be NUL-terminated
   * The strlcpy() function copies up to size - 1 characters from the
   * NUL-terminated string src to dst, NUL-terminating the result.
   * The strlcpy() function returns the total length of the string it tried
   * to create. That means the length of src.
   * @param dst destination buffer
   * @param src source NUL-terminated string
   * @param size size of destination buffer
   * @return length of src string
   */
  size_t
  strlcpy(char* dst, const char* src, size_t size) noexcept;

  /**
   * The strlcat() function concatenate strings.  It is designed to be safer,
   * more consistent, and less error prone replacements for strncat(3).
   * Unlike that function, strlcat() takes the full size of the buffer (not
   * just the length) and guarantees to NUL-terminate the result (as long as
   * there is at least one byte free in dst). Note that you should include a
   * byte for the NUL in size. Also note that strlcat() only operates on true
   * "C" strings.  This means that both src and dst must be NUL-terminated.
   * The strlcat() function appends the NUL-terminated string src to the end
   * of dst.  It will append at most size - strlen(dst) - 1 bytes,
   * NUL-terminating the result.
   * The strlcat() functions returns the total length of the string it tried
   * to create.  That means the initial length of dst plus the length of src.
   * While this may seem somewhat confusing it was done to make truncation
   * detection simple.
   * Note however, that if strlcat() traverses size characters without finding
   * a NUL, the length of the string is considered to be size and the
   * destination string will not be NUL-terminated (since there was no space
   * for the NUL). This keeps strlcat() from running off the end of a string.
   * In practice this should not happen (as it means that either size is
   * incorrect or that dst is not a proper "C" string). The check exists to
   * prevent potential security problems in incorrect code.
   * @param dst destination buffer containing NUL-terminated string
   * @param src source NUL-terminated string
   * @param size size of destination buffer
   * @return length of src string plus length of original string in
   * destination buffer
   */
  size_t
  strlcat(char* dst, const char* src, size_t size) noexcept;

  /**
   * Encodes data with base64 algorithm using '+', '/' and '='
   * @param dest encoded string (in one line)
   * @param src source data
   * @param size source data size
   * @param padding add padding or not if any
   */
  void
  base64_encode(std::string& dest, const void* src, size_t size,
                bool padding = true) /*throw (Gears::Exception)*/;

  /**
   * Encodes data with base64 algorithm
   * @param dest encoded string (in one line)
   * @param src source data
   * @param size source data size
   * @param padding add padding or not if any
   * @param fill fill [lower] bits between data and padding
   */
  void
  base64mod_encode(std::string& dest, const void* src, size_t size,
                   bool padding = true, uint8_t fill = 0) /*throw (Gears::Exception)*/;

  /**
   * Decodes data encoded with base64 algorithm
   * @param dst decoded data
   * @param src encoded string
   * @param padding if padding is expected or not
   * @param fill filled bits result, if zero - checking is performed
   */
  void
  base64mod_decode(std::string& dst, const Gears::SubString& src,
                   bool padding = true, uint8_t* fill = 0)
    /*throw (InvalidFormatException, Gears::Exception)*/;

  /**
   * Calculates size of data after base64 encoding
   * @param original_size data size
   * @param padding if padding is added or not if any
   * @return encoded data size
   */
  constexpr
  size_t
  base64mod_encoded_size(size_t original_size, bool padding = true)
    noexcept;

  /**
   * Calculates maximal size of data after base64 decoding
   * Resulted size may be one or two bytes less
   * @param original_size data size
   * @return decoded data size
   */
  constexpr
  size_t
  base64mod_max_decoded_size(size_t original_size) noexcept;

  /**
   * Calculates number of bits may be hid
   * right between data and padding.
   * @return number to bits
   */
  constexpr
  size_t
  base64mod_fill_size(size_t original_size) noexcept;

  /**
   * Encodes data according to MIME rules (using %XX form)
   * @param src source data
   * @param dst encoded string
   */
  void
  mime_url_encode(const Gears::SubString& src, std::string& dst)
    /*throw (Gears::Exception)*/;

  /**
   * Decodes data according to MIME rules (replacing %XX substrings)
   * @param src encoded string
   * @param dst decoded string
   * @param strict throw exception if the source string contains errors
   */
  void
  mime_url_decode(const Gears::SubString& src, std::string& dst,
                  bool strict = true)
    /*throw (Gears::Exception, InvalidFormatException)*/;

  /**
   * Performs in place decoding according to MIME rules
   * @param text as input - encoded string, as output - decoded string
   */
  void
  mime_url_decode(std::string& text)
    /*throw (Gears::Exception, InvalidFormatException)*/;

  enum XML_UNIT
  {
    XU_TEXT = 0x1,
    XU_ATTRIBUTE = 0x2,
    XU_PRESERVE_UTF8 = 0x4
  };

  /**
   * Encodes source wide string with XML rules
   * @param src source string
   * @param dst encoded string
   * @param units encoding options
   * XU_TEXT - n/a
   * XU_ATTRIBUTE - encodes apostrophe and quote characters
   * XU_PRESERVE_UTF8 - if set encodes wchar_t as UTF-8 otherwise as &x#XXXX
   */
  void
  xml_encode(const wchar_t* src, std::string& dst,
             unsigned long units = XU_TEXT | XU_ATTRIBUTE)
    /*throw (Gears::Exception)*/;

  /**
   * Encodes source UTF-8 string with XML rules
   * @param src source string
   * @param dst encoded string
   * @param units encoding options
   * XU_TEXT - n/a
   * XU_ATTRIBUTE - encodes apostrophe and quote characters
   * XU_PRESERVE_UTF8 - if set encodes wchar_t as UTF-8
   * otherwise as &x#XXXX
   */
  void
  xml_encode(const char* src, std::string& dst,
             unsigned long units = XU_TEXT | XU_ATTRIBUTE)
    /*throw (InvalidFormatException, Gears::Exception)*/;

  /**
   * Decodes XML-encoded string
   * @param src source encoded string
   * @param dst result decoded string
   */
  void
  xml_decode(const Gears::SubString& src, std::string& dst)
    /*throw (InvalidFormatException, Gears::Exception)*/;

  /**
   * Encodes source string with JS unicode rules (\\uXXXX form)
   * @param src source string
   * @param dst encoded string
   */
  void
  js_unicode_encode(const char* src, std::string& dst)
    /*throw (InvalidFormatException, Gears::Exception)*/;

  /**
   * Decodes source string with JS rules (special uXXXX form).
   * @param src source string
   * @param dest destination string
   * @param strict throw exceptions on invalid encodings
   * @param special special symbol
   */
  void
  js_unicode_decode(const Gears::SubString& src, std::string& dest,
                    bool strict = true, char special = '\\')
    /*throw (InvalidFormatException, Gears::Exception)*/;

  /**
   * Encodes source string with JS rules (\\xXX form)
   * @param src source string
   * @param dst encoded string
   */
  void
  js_encode(const char* src, std::string& dst)
    /*throw (Gears::Exception)*/;

  /**
   * Escapes symbols disallowed in JSON strings
   * @param src source string
   * @return escaped string
   */
  std::string
  json_escape(const SubString& src) /*throw (Gears::Exception)*/;

  /**
   * Performs Punycode encode according to RFC3492
   * @param input wide string to encode
   * @param output encoded ASCII string
   * @return if converted successfully
   */
  bool
  punycode_encode(const WSubString& input, std::string& output)
    /*throw (Gears::Exception)*/;

  /**
   * Performs Punycode decode according to RFC3492
   * @param input ASCII string to decode
   * @param output decoded wide string
   * @return if converted successfully
   */
  bool
  punycode_decode(const SubString& input, std::wstring& output)
    /*throw (Gears::Exception)*/;
    
  /**
   * Encodes source string with CSV (RFC4180) rules
   * @param src source string
   * @param dst encoded string
   * @param separator char of separator for csv values
   * @return dst
   */
  std::string&
  csv_encode(const char* src, std::string& dst, char separator = ',')
    /*throw (Gears::Exception)*/;

  /**
   * Converts UTF8 string into wchar_t one
   * @param src source UTF-8 string
   * @return zero terminated wchar_t string
   */
  Gears::ArrayWChar
  utf8_to_wchar(const Gears::SubString& src)
    /*throw (Gears::Exception, InvalidFormatException)*/;

  /**
   * Converts wchar_t string into UTF-8 one
   * @param src source wchar_t string
   * @param str resulted UTF-8 string
   */
  void
  wchar_to_utf8(const wchar_t* src, std::string& str)
    /*throw (Gears::Exception)*/;

  /**
   * Converts wchar_t string into UTF-8 one
   * @param src source wchar_t string
   * @param str resulted UTF-8 string
   */
  void
  wchar_to_utf8(const Gears::WSubString& src, std::string& str)
    /*throw (Gears::Exception)*/;

  /**
   * Converts wchar_t into UTF-8 string, and appends it to string
   * @param src wchar_t to convert
   * @param str UTF-8 string to append to
   */
  void
  wchar_to_utf8(wchar_t src, std::string& str)
    /*throw (Gears::Exception)*/;

  /**
   * Retrieves correct UTF-8 string with specified maximal length
   * @param src source string
   * @param max_octets maximal substring length in octets
   * @param dst destination string
   * @return false if source string is found to be non UTF-8 compliant,
   * true if successful
   */
  bool
  utf8_substr(
    const Gears::SubString& src, size_t max_octets,
    Gears::SubString& dst) noexcept;

  /**
   * Removes characters defined in a set of symbols
   * from the beginning and end of the string
   * @param str trimming substring
   * @param trim_set Defines a set of characters to remove,
   * default value is Ascii::SPACE
   */
  void
  trim(
    SubString& str,
    const Ascii::CharCategory& trim_set = Ascii::SPACE)
    noexcept;

  /**
   * Removes characters defined in a set of symbols
   * from the beginning and end of the string
   * @param str trimming substring
   * @param dest destination string
   * @param trim_set Defines a set of characters to remove,
   * default value is Ascii::SPACE
   */
  void
  trim(const SubString& str, std::string& dest,
    const Ascii::CharCategory&
     trim_set = Ascii::SPACE)
    /*throw (Gears::Exception)*/;

  /**
   * Removes characters defined in a set of symbols
   * from the beginning and end of the string
   * @param str trimming substring
   * @param trim_set Defines a set of characters to remove,
   * default value is Ascii::SPACE
   * @return trimmed string
   */
  Gears::SubString
  trim_ret(
    SubString str,
    const Ascii::CharCategory& trim_set = Ascii::SPACE)
    noexcept;

  /**
   * Finds and replaces all sequences of symbols from Utf8Category
   * to replace string.
   * @param dest result put here.
   * @param str source string
   * @param replacement - character that replace sequences of.
   * @param to_replace all sequences of chars from this category, will
   * be replaced by replace.
   * @return false if ill-formed UTF8 sequences are found in
   * the source string (simple check).
   */
  bool
  flatten(
    std::string& dest, const Gears::SubString& str,
    const SubString& replacement = SubString(" ", 1),
    const Utf8Category& to_replace = UNICODE_SPACES)
    /*throw (Gears::Exception)*/;

  /**
   * Replaces every occurrence of "to_find" in "str" with "to_replace"
   * and puts result into dst.
   * "######" with ("##" => "#" rule) is turned into "###".
   * @param str source string to process
   * @param dst destination string to put result into
   * @param to_find substring to replace, if it's empty no replacement
   * takes place
   * @param to_replace replacement substring
   */
  void
  replace(const Gears::SubString& str, std::string& dst,
          const Gears::SubString& to_find, const Gears::SubString& to_replace)
    /*throw (Gears::Exception)*/;

  /**
   * Strip directory from file name
   * @param path file name optionally containing directory
   * @return file name without directories prefix
   */
  const char*
  base_name(const char* path) noexcept;

  /**
   * Converts integer value into string
   * @param value value to convert
   * @param str buffer to convert to (zero terminated)
   * @param size its size
   * @return number of characters written (without trailing zero)
   * (0 indicates error)
   */
  template <typename Integer>
  size_t
  int_to_str(Integer value, char* str, size_t size) noexcept;

  /**
   * Wrapper for int_to_str function having buffer inside
   * Used as void f(const Gears::SubString&); f(IntToStr(1));
   */
  class IntToStr : private Gears::Uncopyable
  {
  public:
    /**
     * Constructor
     * Calls int_to_str function
     */
    template <typename Integer>
    explicit
    IntToStr(Integer value) noexcept;

    /**
     * Returns reference to the internal buffer
     */
    SubString
    str() const noexcept;

    /**
     * Returns reference to the internal buffer
     */
    operator SubString() const noexcept;

  private:
    size_t length_;
    char buf_[32];
  };

  /**
   * Converts substring into integer value
   * @param str substring to convert
   * @param value resulted integer value
   * @result if conversion completed successfully or not
   */
  template <typename Integer>
  bool
  str_to_int(const Gears::SubString& str, Integer& value) noexcept;

  /**
   * InverseCategory transposes owned() and derived
   * member functions of the underlying functor.
   */
  template <class Category>
  class InverseCategory : private Category
  {
  public:
    /**
     * Constructor
     */
    InverseCategory() /*throw (Gears::Exception)*/;

    /**
     * Constructor
     * @param args opaque parameters to constructor
     */
    template <typename... T>
    explicit
    InverseCategory(T... args) /*throw (Gears::Exception)*/;

    /**
     * Checks if character is not in the underlying set
     * @param ch character to test
     * @return Unpresence of the character in the set
     */
    template <typename Character>
    bool
    is_owned(Character ch) const noexcept;

    /**
     * Functor-compatible way to call is_owned
     * @param ch The same as in is_owned
     */
    template <typename Character>
    bool
    operator ()(Character ch) const noexcept;

    /**
     * Finds the first symbol in the string which DOES NOT belong to
     * the set that underlying functor recognizes.
     * @param begin beginning of the string to search in
     * @param end end of the string to search in
     * @param octets length of found symbol
     * @return Pointer to found symbol or end if none
     * NULL may be returned in case of error, see docs for the
     * underlying functor
     */
    const char*
    find_owned(
      const char* begin, const char* end,
      unsigned long* octets = 0) const noexcept;

    /**
     * Finds the first symbol in the string which DOES belong to
     * the set that underlying functor recognizes.
     * @param begin beginning of the string to search in
     * @param end end of the string to search in
     * @param octets length of found symbol
     * @return Pointer to found symbol or end if none
     * NULL may be returned in case of error, see docs for the
     * underlying functor
     */
    const char*
    find_nonowned(
      const char* begin, const char* end,
      unsigned long* octets = 0) const noexcept;

    /**
     * Finds the last symbol in the string which does not belong to the
     * underlying set
     * @param pos The pointer to char beyond the string to search in
     * @param start The pointer to begin of string to search in. Interval
     * [start, pos) will be looked in.
     * @param octets The length of found symbol
     * @return Pointer to found symbol or original value of pos if none.
     * NULL may be returned in case of error, see docs for the
     * underlying functor
     */
    const char*
    rfind_owned(
      const char* pos, const char* start,
      unsigned long* octets = 0) const noexcept;

    /**
     * Finds the last symbol in the string which belongs to the
     * underlying set
     * @param pos The pointer to char beyond the string to search in
     * @param start The pointer to begin of string to search in. Interval
     * [start, pos) will be looked in.
     * @param octets The length of found symbol
     * @return Pointer to found symbol or original value of pos if not found.
     * NULL may be returned in case of error, see docs for the
     * underlying functor
     */
    const char*
    rfind_nonowned(
      const char* pos, const char* start,
      unsigned long* octets = 0) const noexcept;
  };

  void
  concat(char* buffer, size_t size)
    noexcept;

  /**
   * Safely concatenates several strings to the string buffer.
   * @param buffer string buffer to concatenate to
   * @param size the size of the buffer
   * @param f string to append
   * @param args strings to append
   */
  template <typename First, typename... Args>
  void
  concat(char* buffer, size_t size, First f, Args... args)
    noexcept;

  /**
   * Encodes data into hex string
   * @param data source data
   * @param size data size
   * @param skip_leading_zeroes if skip all leading zeroes
   * @return encoded hex string
   */
  std::string
  hex_encode(
    const unsigned char* data,
    size_t size,
    bool skip_leading_zeroes) /*throw (Gears::Exception)*/;

  /**
   * Decodes hex src into array of bytes
   * @param src source string
   * @param dst destination array of bytes
   * @param allow_odd_string if odd length string is allowed
   * @return length of destination array
   */
  size_t
  hex_decode(
    SubString src,
    Gears::ArrayByte& dst,
    bool allow_odd_string = false)
    /*throw (Gears::Exception, InvalidFormatException)*/;
} // namespace StringManip
} // namespace Gears

#include <gears/StringManip.ipp>
#include <gears/StringManip.tpp>
#include <gears/Tokenizer.hpp>

#endif
