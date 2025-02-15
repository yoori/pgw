#ifndef GEARS_TOKENIZER_HPP_
#define GEARS_TOKENIZER_HPP_

#include <gears/AsciiStringManip.hpp>
#include <gears/Uncopyable.hpp>

namespace Gears
{
  namespace StringManip
  {
    typedef const Ascii::Char3Category<' ', '\n', '\t'>
      TokenizerDefaultSeparators;

    namespace Helper
    {
      template <typename Category>
      struct SplitterState : private Gears::Uncopyable
      {
        explicit
        SplitterState(const SubString& str) /*throw (Gears::Exception)*/;
        SplitterState(const SubString& str, Category category)
          /*throw (Gears::Exception)*/;

        Category category;

        const char* str;
        const char* const END;

        const char* separator;
        bool error;
      };

      template <const bool EMPTY>
      struct GetToken
      {
        template <typename SplitterState>
        static
        bool
        get_token(SplitterState& state, SubString& token)
          /*throw (Gears::Exception)*/;
      };

      template <>
      struct GetToken<false>
      {
        template <typename SplitterState>
        static
        bool
        get_token(SplitterState& state, SubString& token)
          /*throw (Gears::Exception)*/;
      };
    };

    template <typename Category = TokenizerDefaultSeparators,
      const bool EMPTY = false>
    class Splitter
    {
    public:
      /**
       * Default constructor using default category constructor
       * @param str SubString to split
       */
      explicit
      Splitter(const SubString& str)
        /*throw (Gears::Exception)*/;

      /**
       * Constructor
       * @param str SubString to split
       * @param category Category to determine separation
       */
      Splitter(const SubString& str, Category category)
        /*throw (Gears::Exception)*/;

      /**
       * Searches for the next token and returns substring describing it
       * @param token resulted token
       * @return if a new token has been found or not
       */
      bool
      get_token(SubString& token) /*throw (Gears::Exception)*/;

      /**
       * Returns separator at the end of found token
       * @return pointer to the separator symbol in the string
       */
      const char*
      get_separator() const noexcept;

      /**
       * If get_token() returned negative it may mean category found
       * the error in the string
       * @return whether or not error has been found in the string
       */
      bool
      is_error() const noexcept;

    private:
      Helper::SplitterState<Category> state_;
    };

    typedef Splitter<const Ascii::CharCategory&> CharSplitter;

    typedef Splitter<Ascii::SepColon> SplitColon;
    typedef Splitter<Ascii::SepComma> SplitComma;
    typedef Splitter<Ascii::SepPeriod> SplitPeriod;
    typedef Splitter<Ascii::SepMinus> SplitMinus;
    typedef Splitter<Ascii::SepSemCol> SplitSemCol;
    typedef Splitter<Ascii::SepAmp> SplitAmp;
    typedef Splitter<Ascii::SepSpace> SplitSpace;
    typedef Splitter<Ascii::SepEq> SplitEq;
    typedef Splitter<Ascii::SepSlash> SplitSlash;
    typedef Splitter<Ascii::SepHash> SplitHash;
    typedef Splitter<Ascii::SepBar> SplitBar;
    typedef Splitter<Ascii::SepNL> SplitNL;
    typedef Splitter<Ascii::SepTab> SplitTab;

    class Tokenizer :
      private Ascii::CharCategory,
      public CharSplitter
    {
    public:
      Tokenizer(const Gears::SubString& str, const char* symbols)
        /*throw (Gears::Exception)*/;
    };


    template <typename Category, typename Callback>
    bool
    divide(const Gears::SubString& str, Category category,
      Callback callback) /*throw (Gears::Exception)*/;
  }
}

namespace Gears
{
  namespace StringManip
  {
    namespace Helper
    {
      //
      // SplitterState class
      //

      template <typename Category>
      SplitterState<Category>::SplitterState(const SubString& str)
        /*throw (Gears::Exception)*/
      : category(),
        str(str.begin()), END(str.end()), error(false)
      {
      }

      template <typename Category>
      SplitterState<Category>::SplitterState(const SubString& str,
        Category category)
        /*throw (Gears::Exception)*/
        : category(category),
          str(str.begin()), END(str.end()), error(false)
      {
      }


      //
      // GetToken class
      //

      template <const bool EMPTY>
      template <typename SplitterState>
      bool
      GetToken<EMPTY>::get_token(SplitterState& state, SubString& token)
        /*throw (Gears::Exception)*/
      {
        if (state.str == state.END)
        {
          return false;
        }

        unsigned long octets_length = 0;
        if ((state.separator =
          state.category.find_owned(state.str, state.END, &octets_length)))
        {
          token.assign(state.str, state.separator);
          state.str = state.separator == state.END ? state.END :
            state.separator + octets_length;
          return true;
        }

        state.error = true;
        return false;
      }

      template <typename SplitterState>
      bool
      GetToken<false>::get_token(SplitterState& state, SubString& token)
        /*throw (Gears::Exception)*/
      {
        if (const char* begin = state.category.find_nonowned(
          state.str, state.END))
        {
          if (const char* end = state.category.find_owned(begin, state.END))
          {
            if (begin == end)
            {
              return false;
            }

            token.assign(begin, end);
            state.separator = state.str = end;
            return true;
          }
        }

        state.error = true;
        return false;
      }
    }


    //
    // Splitter class
    //

    template <typename Category, const bool EMPTY>
    Splitter<Category, EMPTY>::Splitter(const SubString& str)
      /*throw (Gears::Exception)*/
      : state_(str)
    {
    }

    template <typename Category, const bool EMPTY>
    Splitter<Category, EMPTY>::Splitter(const SubString& str,
      Category category)
      /*throw (Gears::Exception)*/
      : state_(str, category)
    {
    }

    template <typename Category, const bool EMPTY>
    bool
    Splitter<Category, EMPTY>::get_token(SubString& token)
      /*throw (Gears::Exception)*/
    {
      return Helper::GetToken<EMPTY>::get_token(state_, token);
    }

    template <typename Category, const bool EMPTY>
    const char*
    Splitter<Category, EMPTY>::get_separator() const noexcept
    {
      return state_.separator;
    }

    template <typename Category, const bool EMPTY>
    bool
    Splitter<Category, EMPTY>::is_error() const noexcept
    {
      return state_.error;
    }

    //
    // Tokenizer class
    //

    inline
    Tokenizer::Tokenizer(const Gears::SubString& str, const char* symbols)
      /*throw (Gears::Exception)*/
      : Ascii::CharCategory(symbols), CharSplitter(str, *this)
    {}

    template <typename Category, typename Callback>
    bool
    divide(const Gears::SubString& str, Category category,
      Callback callback)
      /*throw (Gears::Exception)*/
    {
      const char* last = str.begin();
      const char* const END = str.end();
      for (;;)
      {
        const char* cur = category.find_owned(last, END);
        if (!cur)
        {
          return false;
        }
        if (cur != last)
        {
          callback.nonowned(Gears::SubString(last, cur));
        }
        if (cur == END)
        {
          break;
        }
        last = cur;
        cur = category.find_nonowned(last, END);
        if (!cur)
        {
          return false;
        }
        if (cur != last)
        {
          callback.owned(Gears::SubString(last, cur));
        }
        if (cur == END)
        {
          break;
        }
        last = cur;
      }
      return true;
    }
  }
}

#endif
