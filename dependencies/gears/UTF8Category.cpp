#include <cassert>
#include <cstring>

#include <gears/UTF8Category.hpp>
#include <gears/UTF8Handler.hpp>
#include <gears/UTF8IsProperty.hpp>

#include <gears/OutputMemoryStream.hpp>

namespace Gears
{
  namespace UnicodeProperty
  {
    const Node TREE_STOP(&TREE_STOP);
  }

  namespace Utf8Set
  {
    Utf8Char
    get_char(const char* symbol, unsigned long* poctets)
      /*throw (Gears::Exception)*/
    {
      Utf8Char utf8char = 0;
      unsigned long octets;
      if (!(octets = UTF8Handler::get_octet_count(*symbol)) || octets > 4)
      {
        if (poctets)
        {
          *poctets = 0;
        }
        return ~static_cast<Utf8Char>(0);
      }

      for (const char* till = symbol + octets; symbol != till; symbol++)
      {
        utf8char = (utf8char << 8) | static_cast<uint8_t>(*symbol);
      }

      if (poctets)
      {
        *poctets = octets;
      }
      return utf8char;
    }

    void
    add_symbol(Utf8Chars& chars, const char* symbol)
      /*throw (Gears::Exception)*/
    {
      chars.add(get_char(symbol));
    }

    void
    add_symbols(Utf8Chars& chars, const char* first, const char* last)
      /*throw (Gears::Exception)*/
    {
      chars.add(get_char(first), get_char(last));
    }
  }

  const Utf8Category UNICODE_SPACES(UnicodeProperty::SPACE_TREE);
  const Utf8Category UNICODE_DIGITS(UnicodeProperty::DIGIT_TREE);
  const Utf8Category UNICODE_LETTERS(UnicodeProperty::LETTER_TREE);
  const Utf8Category UNICODE_LOWER_LETTERS(
    UnicodeProperty::LETTER_LOWER_TREE);
  const Utf8Category UNICODE_TITLE_LETTERS(
    UnicodeProperty::LETTER_TITLE_TREE);
  const Utf8Category UNICODE_UPPER_LETTERS(
    UnicodeProperty::LETTER_UPPER_TREE);

  Utf8Category::Utf8Category(const char* symbols, bool check_zero)
    /*throw (Gears::Exception, InvalidArgument)*/
    : nodes_(), need_cleaning_(true)
  {
    static const char* FUN = "Utf8Category::Utf8Category()";

    if (!symbols)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": NULL input string";
      throw InvalidArgument(ostr.str());
    }

    Utf8Set::Utf8Chars chars;

    if (check_zero)
    {
      chars.add(0);
    }

    Utf8Set::Utf8Char last = 0;
    bool advanced = false;

    while (*symbols)
    {
      unsigned long octets = 0;
      Utf8Set::Utf8Char cur = Utf8Set::get_char(symbols, &octets);
      if (!octets)
      {
        Gears::ErrorStream ostr;
        ostr << FUN << ": non UTF-8 symbol in argument '" << symbols << "'";
        throw InvalidArgument(ostr.str());
      }
      symbols += octets;

      if (advanced)
      {
        chars.add(last, cur);
        advanced = false;
      }
      else
      {
        if (cur == '-' && *symbols && last)
        {
          advanced = true;
        }
        else
        {
          chars.add(cur);
          last = cur;
        }
      }
    }

    init_(chars);
  }

  Utf8Category::Utf8Category(const Utf8Set::Utf8Chars& chars)
    /*throw (Gears::Exception)*/
    : nodes_(), need_cleaning_(true)
  {
    init_(chars);
  }

  Utf8Category::~Utf8Category() noexcept
  {
    if (need_cleaning_)
    {
      clear_();
    }
  }

  void
  Utf8Category::swap(Utf8Category& category) noexcept
  {
    char buf[sizeof(nodes_)];

    memcpy(buf, nodes_, sizeof(buf));
    memcpy(const_cast<UnicodeProperty::Node*>(nodes_),
      category.nodes_, sizeof(buf));
    memcpy(const_cast<UnicodeProperty::Node*>(category.nodes_),
      buf, sizeof(buf));
    std::swap(category.need_cleaning_, need_cleaning_);
  }

  const char*
  Utf8Category::find_owned(const char* str, unsigned long* octets) const
    noexcept
  {
    for (;;)
    {
      unsigned long octets_count;

      // Simple check for validness...
      if (!(octets_count = UTF8Handler::get_octet_count(*str)))
      {
        return 0;
      }
      // ...and availability
      for (size_t i = 1; i < octets_count; i++)
      {
        if (!str[i])
        {
          return 0;
        }
      }

      if (is_owned(str))
      {
        if (octets)
        {
          *octets = octets_count;
        }
        return str;
      }

      if (!*str)
      {
        break;
      }

      str += octets_count;
    }

    return 0;
  }

  const char*
  Utf8Category::find_owned(const char* begin, const char* end,
    unsigned long* octets) const noexcept
  {
    while (begin < end)
    {
      unsigned long octets_count;

      // Simple check for validness...
      if (!(octets_count = UTF8Handler::get_octet_count(*begin)))
      {
        return 0;
      }
      // ...and availability
      if (static_cast<size_t>(end - begin) < octets_count)
      {
        return 0;
      }

      if (is_owned(begin))
      {
        if (octets)
        {
          *octets = octets_count;
        }
        return begin;
      }

      begin += octets_count;
    }

    return end;
  }

  const char*
  Utf8Category::find_nonowned(const char* str, unsigned long* octets) const
    noexcept
  {
    for (;;)
    {
      unsigned long octets_count;

      // Simple check for validness...
      if (!(octets_count = UTF8Handler::get_octet_count(*str)))
      {
        return 0;
      }
      // ...and availability
      for (size_t i = 1; i < octets_count; i++)
      {
        if (!str[i])
        {
          return 0;
        }
      }

      if (!is_owned(str))
      {
        if (octets)
        {
          *octets = octets_count;
        }
        return str;
      }

      if (!*str)
      {
        break;
      }

      str += octets_count;
    }

    return 0;
  }

  const char*
  Utf8Category::find_nonowned(const char* begin, const char* end,
    unsigned long* octets) const noexcept
  {
    while (begin < end)
    {
      unsigned long octets_count;

      // Simple check for validness...
      if (!(octets_count = UTF8Handler::get_octet_count(*begin)))
      {
        return 0;
      }
      // ...and availability
      if (static_cast<size_t>(end - begin) < octets_count)
      {
        return 0;
      }

      if (!is_owned(begin))
      {
        if (octets)
        {
          *octets = octets_count;
        }
        return begin;
      }

      begin += octets_count;
    }

    return end;
  }

  const char*
  Utf8Category::rfind_owned(const char* pos, const char* start,
    unsigned long* octets) const noexcept
  {
    const char* last_review = pos;
    const char* current = pos;
    while (current > start)
    {
      --current;
      if ((*current & 0xC0) != 0x80)
      {
        // Simple check for validness...
        size_t current_range = last_review - current;
        if (UTF8Handler::get_octet_count(*current) != current_range)
        {
          return 0;
        }
        if (is_owned(current))
        {
          if (octets)
          {
            *octets = current_range;
          }
          return current;
        }
        last_review = current;
      }
    }

    return pos;
  }

  const char*
  Utf8Category::rfind_nonowned(const char* pos, const char* start,
    unsigned long* octets) const noexcept
  {
    const char* last_review = pos;
    const char* current = pos;
    while (current > start)
    {
      --current;
      if ((*current & 0xC0) != 0x80)
      {
        // Simple check for validness...
        size_t current_range = last_review - current;
        if (UTF8Handler::get_octet_count(*current) != current_range)
        {
          return 0;
        }
        if (!is_owned(current))
        {
          if (octets)
          {
            *octets = current_range;
          }
          return current;
        }
        last_review = current;
      }
    }

    return pos;
  }

  void
  Utf8Category::clear_() noexcept
  {
    for (int i = 0; i < 256; i++)
    {
      unsigned long depth = UTF8Handler::get_octet_count(i);
      if (depth > 2)
      {
        clear_(nodes_[i].node, depth - 2);
      }
    }
  }

  void
  Utf8Category::clear_(const UnicodeProperty::Node* node,
    unsigned long depth) noexcept
  {
    if (!node || node == &UnicodeProperty::TREE_STOP)
    {
      return;
    }

    if (--depth)
    {
      for (int i = 0; i < 64; i++)
      {
        clear_(node[i].node, depth);
      }
    }

    delete [] node;
  }

  void
  Utf8Category::init_(const Utf8Set::Utf8Chars& chars) /*throw (Gears::Exception)*/
  {
    try
    {
      for (unsigned i = 0; i < 256; i++)
      {
        unsigned long depth = UTF8Handler::get_octet_count(i);
        switch (depth)
        {
        case 0:
          break;

        case 1:
          const_cast<UnicodeProperty::Node&>(nodes_[i]).node =
            chars.belongs(i) ? &UnicodeProperty::TREE_STOP : 0;
          break;

        default:
          init_interval_(chars, const_cast<UnicodeProperty::Node&>(
            nodes_[i]), i, depth - 2);
          break;
        }
      }
    }
    catch (const Gears::Exception&)
    {
      clear_();
      throw;
    }
  }

  void
  Utf8Category::init_interval_(const Utf8Set::Utf8Chars& chars,
    UnicodeProperty::Node& node,
    Utf8Set::Utf8Char prefix, unsigned long depth_left)
    /*throw (Gears::Exception)*/
  {
    if (depth_left)
    {
      switch (check_interval_(chars, prefix, depth_left))
      {
      case Utf8Set::Utf8Chars::CS_NONE:
        node.node = 0;
        break;

      case Utf8Set::Utf8Chars::CS_ALL:
        node.node = &UnicodeProperty::TREE_STOP;
        break;

      case Utf8Set::Utf8Chars::CS_SOME:
        UnicodeProperty::Node* middle = new UnicodeProperty::Node[64];
        node.node = middle;
        prefix <<= 8;
        prefix += 0x80;
        depth_left--;
        for (Utf8Set::Utf8Char stop = prefix + 64; prefix < stop;
          prefix++, middle++)
        {
          init_interval_(chars, *middle, prefix, depth_left);
        }
      }
    }
    else
    {
      prefix <<= 8;
      prefix += 0x80;
      switch (chars.check_presence(prefix, prefix + 63))
      {
      case Utf8Set::Utf8Chars::CS_NONE:
        node.leaf = 0;
        break;

      case Utf8Set::Utf8Chars::CS_ALL:
        node.leaf = ~static_cast<UnicodeProperty::TreeLeaf>(0);
        break;

      case Utf8Set::Utf8Chars::CS_SOME:
        node.leaf = 0;
        UnicodeProperty::TreeLeaf flag = 1;
        for (Utf8Set::Utf8Char stop = prefix + 64; prefix < stop;
          flag <<= 1, prefix++)
        {
          if (chars.belongs(prefix))
          {
            node.leaf |= flag;
          }
        }
        break;
      }
    }
  }

  Utf8Set::Utf8Chars::CheckStatus
  Utf8Category::check_interval_(const Utf8Set::Utf8Chars& chars,
    Utf8Set::Utf8Char prefix, unsigned long depth_left)
    /*throw (Gears::Exception)*/
  {
    if (depth_left)
    {
      {
        unsigned long shift = (depth_left + 1) * 8;
        Utf8Set::Utf8Chars::CheckStatus status = chars.check_presence(
          prefix << shift, ((prefix + 1) << shift) - 1);

        if (status != Utf8Set::Utf8Chars::CS_SOME)
        {
          return status;
        }
      }

      prefix <<= 8;
      prefix += 0x80;
      depth_left--;

      bool all = true;
      bool none = true;

      for (Utf8Set::Utf8Char stop = prefix + 64; prefix < stop; prefix++)
      {
        switch (check_interval_(chars, prefix, depth_left))
        {
        case Utf8Set::Utf8Chars::CS_NONE:
          if (!none)
          {
            return Utf8Set::Utf8Chars::CS_SOME;
          }
          all = false;
          break;

        case Utf8Set::Utf8Chars::CS_ALL:
          if (!all)
          {
            return Utf8Set::Utf8Chars::CS_SOME;
          }
          none = false;
          break;

        case Utf8Set::Utf8Chars::CS_SOME:
          return Utf8Set::Utf8Chars::CS_SOME;
        }
      }

      return none ? Utf8Set::Utf8Chars::CS_NONE :
        Utf8Set::Utf8Chars::CS_ALL;
    }
    else
    {
      prefix <<= 8;
      prefix += 0x80;
      return chars.check_presence(prefix, prefix + 63);
    }
  }
}
