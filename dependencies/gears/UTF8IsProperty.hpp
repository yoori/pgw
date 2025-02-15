#ifndef UTF8_IS_PROPERTY_HPP
#define UTF8_IS_PROPERTY_HPP

#include <gears/UTF8NArcTree.hpp>

namespace Gears
{
  /**
   * Check that UTF-8 encoded string contain space Unicode character,
   * buffer overrun IS NOT checked.
   * @param str input string
   * @return true for space Unicode symbols.
   */
  bool
  is_space(const char* str) noexcept;

  /**
   * Check that UTF-8 encoded string contain digit Unicode character,
   * buffer overrun IS NOT checked.
   * @param str input string
   * @return true for digit Unicode symbols.
   */
  bool
  is_digit(const char* str) noexcept;

  /**
   * Check that UTF-8 encoded string contain letter Unicode character,
   * buffer overrun IS NOT checked.
   * @param str input string
   * @return true for letter Unicode symbols.
   */
  bool
  is_letter(const char* str) noexcept;

  /**
   * Check that UTF-8 encoded string contain lower letter Unicode character,
   * buffer overrun IS NOT checked.
   * @param str input string
   * @return true for lower letter Unicode symbols.
   */
  bool
  is_lower_letter(const char* str) noexcept;

  /**
   * Check that UTF-8 encoded string contain title letter Unicode character,
   * buffer overrun IS NOT checked.
   * @param str input string
   * @return true for title letter Unicode symbols.
   */
  bool
  is_title_letter(const char* str) noexcept;

  /**
   * Check that UTF-8 encoded string contain upper letter Unicode character,
   * buffer overrun IS NOT checked.
   * @param str input string
   * @return true for upper letter Unicode symbols.
   */
  bool
  is_upper_letter(const char* str) noexcept;
} // namespace String

//////////////////////////////////////////////////////////////////////////
//        Implementation
//////////////////////////////////////////////////////////////////////////

namespace Gears
{
  namespace UnicodeProperty
  {
    extern const TreeStartNode SPACE_TREE;
    extern const TreeStartNode DIGIT_TREE;
    extern const TreeStartNode LETTER_TREE;
    extern const TreeStartNode LETTER_LOWER_TREE;
    extern const TreeStartNode LETTER_TITLE_TREE;
    extern const TreeStartNode LETTER_UPPER_TREE;
    extern const TreeStartNode BIDI_L_TREE;
    extern const TreeStartNode BIDI_RAL_TREE;
  } // namespace UnicodeProperty

  inline
  bool
  is_space(const char* str) noexcept
  {
    return UnicodeProperty::belong(UnicodeProperty::SPACE_TREE, str);
  }

  inline
  bool
  is_digit(const char* str) noexcept
  {
    return UnicodeProperty::belong(UnicodeProperty::DIGIT_TREE, str);
  }

  inline
  bool
  is_letter(const char* str) noexcept
  {
    return UnicodeProperty::belong(UnicodeProperty::LETTER_TREE, str);
  }

  inline
  bool
  is_lower_letter(const char* str) noexcept
  {
    return UnicodeProperty::belong(UnicodeProperty::LETTER_LOWER_TREE, str);
  }

  inline
  bool
  is_title_letter(const char* str) noexcept
  {
    return UnicodeProperty::belong(UnicodeProperty::LETTER_TITLE_TREE, str);
  }

  inline
  bool
  is_upper_letter(const char* str) noexcept
  {
    return UnicodeProperty::belong(UnicodeProperty::LETTER_UPPER_TREE, str);
  }
} // namespace String

#endif
