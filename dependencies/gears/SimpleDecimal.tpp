#include <iomanip>
#include <cstring>

namespace Gears
{
  //
  // SimpleDecimal class
  //

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  const unsigned SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::PACK_SIZE;

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  const Base SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::INVALID_FLAG_;

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename Integer, typename Fraction>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::construct_(bool negative,
    Integer integer, Fraction fraction) /*throw (Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::construct_()";

    DecimalIntegerCheck<Integer>();
    DecimalIntegerCheck<Fraction>();

    if (DecimalHelper::exceeds(fraction, Parent::MAX_FRACTION_))
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": fraction " << fraction << " is not less than " <<
        static_cast<typename Parent::CalcType>(MAX_FRACTION_);
      throw Overflow(ostr.str());
    }
    if (DecimalHelper::exceeds(integer, MAX_INTEGER_))
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": integer " << integer << " is not less than " <<
        static_cast<typename Parent::CalcType>(MAX_INTEGER_);
      throw Overflow(ostr.str());
    }
    negative_ = negative;
    data_ = static_cast<Base>(integer) * MAX_FRACTION_ +
      static_cast<Base>(fraction);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename Integer>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::construct_(
    Integer integer, unsigned power) /*throw (Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::construct_()";

    DecimalIntegerCheck<Integer>();

    if (power >= std::numeric_limits<Integer>::digits10 + FRACTION_RANK ||
      !integer)
    {
      negative_ = false;
      data_ = 0;
      return;
    }

    DecimalHelper::split(integer, negative_);

    if (power == FRACTION_RANK)
    {
      if (DecimalHelper::exceeds(integer, MAX_VALUE_))
      {
        Gears::ErrorStream ostr;
        ostr << FUN << ": integer " <<
          integer / DecimalHelper::pow10<Integer>(power) <<
          " is not less than " <<
          static_cast<typename Parent::CalcType>(MAX_INTEGER_);
        throw Overflow(ostr.str());
      }
      data_ = static_cast<Base>(integer);
    }
    else if (power > FRACTION_RANK)
    {
      integer /= DecimalHelper::pow10<Integer>(power - FRACTION_RANK);
      if (DecimalHelper::exceeds(integer, MAX_VALUE_))
      {
        Gears::ErrorStream ostr;
        ostr << FUN << ": integer " << integer / MAX_FRACTION_ <<
          " is not less than " <<
          static_cast<typename Parent::CalcType>(MAX_INTEGER_);
        throw Overflow(ostr.str());
      }
      data_ = static_cast<Base>(integer);
    }
    else
    {
      Base mul = DecimalHelper::pow10<Base>(FRACTION_RANK - power);
      if (DecimalHelper::exceeds(integer, MAX_VALUE_ / mul))
      {
        Gears::ErrorStream ostr;
        ostr << FUN << ": integer " <<
          integer / DecimalHelper::pow10<Integer>(power) <<
          " is not less than " <<
          static_cast<typename Parent::CalcType>(MAX_INTEGER_);
        throw Overflow(ostr.str());
      }
      data_ = static_cast<Base>(integer) * mul;
    }
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::construct_(
    const Gears::SubString& str) /*throw (Overflow, NotNumber)*/
  {
    static const char* FUN = "SimpleDecimal<>::construct_()";

    std::ios_base::iostate iostate(std::ios_base::goodbit);
    const char* result =
      DecimalHelper::extract_decimal<TOTAL_RANK, FRACTION_RANK>(
        str.begin(), str.end(), iostate, data_, negative_);

    if (iostate & std::ios_base::failbit)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": '" << str << "': " << result;
      throw Overflow(ostr.str());
    }

    if (result)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": '" << str << "': " << result;
      throw NotNumber(ostr.str());
    }

    if (!(iostate & std::ios_base::eofbit))
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": string '" << str << "' contains non-digit character";
      throw NotNumber(ostr.str());
    }
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::SimpleDecimal() throw ()
    : negative_(false), data_(INVALID_FLAG_)
  {
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename Integer, typename Fraction>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::SimpleDecimal(
    bool negative, Integer integer, Fraction fraction) /*throw (Overflow)*/
  {
    construct_(negative, integer, fraction);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename Integer>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::SimpleDecimal(
    Integer integer, unsigned power) /*throw (Overflow)*/
  {
    construct_(integer, power);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::SimpleDecimal(
    const Gears::SubString& str) /*throw (Overflow, NotNumber)*/
  {
    construct_(str);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename General>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::SimpleDecimal(
    General num) /*throw (Overflow, NotNumber)*/
  {
    Gears::OutputStackStream<TOTAL_RANK + 3 + !INTEGER_RANK> ostr;
    ostr << std::setprecision(FRACTION_RANK) << std::fixed << num;
    construct_(ostr.str());
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename DiffBase, const unsigned DIFF_TOTAL,
    const unsigned DIFF_FRACTION>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::SimpleDecimal(
    const SimpleDecimal<DiffBase, DIFF_TOTAL, DIFF_FRACTION>& diff)
    /*throw (Overflow)*/
  {
    static_assert(DIFF_FRACTION <= SimpleDecimal::FRACTION_RANK,
      "different SimpleDecimal is more precise");

    construct_(diff.data_, DIFF_FRACTION);
    negative_ = diff.negative_;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename ToInteger>
  ToInteger
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::integer() const
    /*throw (Overflow, Sign)*/
  {
    static const char* FUN = "SimpleDecimal<>::integer()";

    assert(data_ != INVALID_FLAG_);

    Base int_part = data_ / MAX_FRACTION_;
    if (static_cast<typename Parent::CalcType>(int_part) >
      static_cast<typename Parent::CalcType>(
        std::numeric_limits<ToInteger>::max()))
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": return type is too narrow to contain the value of " <<
        static_cast<typename Parent::CalcType>(int_part);
      throw Overflow(ostr.str());
    }

    if (negative_ && int_part && !std::numeric_limits<ToInteger>::is_signed)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": return type is unsigned "
        "but the value to return is negative";
      throw Sign(ostr.str());
    }
    return negative_ ? - static_cast<ToInteger>(int_part) :
      static_cast<ToInteger>(int_part);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename ToInteger>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::to_integer(
    ToInteger& val) const /*throw (Overflow, Sign)*/
  {
    val = integer<ToInteger>();
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename ToFloating>
  ToFloating
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::floating() const throw ()
  {
    static_assert(!std::numeric_limits<ToFloating>::is_integer,
      "Floating type is integer");
    static_assert(std::numeric_limits<ToFloating>::is_signed,
      "Floating type is not signed");

    assert(data_ != INVALID_FLAG_);

    ToFloating ret(static_cast<ToFloating>(data_) /
      static_cast<ToFloating>(MAX_FRACTION_));
    return negative_ ? -ret : ret;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  template <typename ToFloating>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::to_floating(
    ToFloating& val) const throw ()
  {
    val = floating<ToFloating>();
  }

  template <typename Base, const unsigned TOTAL, const unsigned FRACTION>
  char*
  SimpleDecimal<Base, TOTAL, FRACTION>::decimal_to_char_(
    char* buf_end) const throw ()
  {
    assert(data_ != INVALID_FLAG_);

    char* buf = buf_end;
    if (!data_)
    {
      *--buf = '0';
      if (FRACTION)
      {
        *--buf = '.';
        *--buf = '0';
      }
      return buf;
    }

    Base elem = data_;
    if (FRACTION) // avoid specilization for FRACTION=0
    {
      Base fraction_part = elem % MAX_FRACTION_;
      if (fraction_part)
      {
        int rest;
        std::size_t frac_index = 0;
        do  // omitting trailing zeros
        {
          rest = fraction_part % 10;
          fraction_part /= 10;
          ++frac_index;
        }
        while (!rest);
        *--buf = rest + '0';
        while (fraction_part)
        {
          *--buf = (fraction_part % 10) + '0';
          fraction_part /= 10;
          ++frac_index;
        }
        for (; frac_index != FRACTION; ++frac_index)
        {
          *--buf = '0';
        }
      }
      else
      {
        *--buf = '0';
      }
      *--buf = '.';
      elem /= MAX_FRACTION_;
    }
    do // write integer part
    {
      *--buf = (elem % 10) + '0';
      elem /= 10;
    }
    while (elem);
    if (negative_)
    {
      *--buf = '-';
    }
    return buf;
  }

  template <typename Base, const unsigned TOTAL,
    const unsigned FRACTION>
  std::string
  SimpleDecimal<Base, TOTAL, FRACTION>::str() const
    /*throw (Gears::Exception)*/
  {
    char buffer[TOTAL + 2];
    char* const BUF_END = buffer + sizeof(buffer);
    return std::string(decimal_to_char_(BUF_END), BUF_END);
  }

  template <typename Base, const unsigned TOTAL, const unsigned FRACTION>
  std::ostream&
  operator <<(std::ostream& ostr,
    const SimpleDecimal<Base, TOTAL, FRACTION>& number)
    /*throw (Gears::Exception)*/
  {
    char buffer[TOTAL + 2];
    char* const BUF_END = buffer + sizeof(buffer);
    char* buf = number.decimal_to_char_(BUF_END);
    // Write resulting, fully-formatted string to stream.
    return ostr.write(buf, BUF_END - buf);
  }

  template <typename Base, const unsigned TOTAL, const unsigned FRACTION>
  std::istream&
  operator >>(std::istream& istr,
    SimpleDecimal<Base, TOTAL, FRACTION>& number)
    /*throw (Gears::Exception)*/
  {
    typename std::istream::sentry ok(istr);
    if (ok)
    {
      std::ios_base::iostate iostate(std::ios_base::goodbit);
      DecimalHelper::extract_decimal<TOTAL, FRACTION>(
        std::istreambuf_iterator<char>(istr),
        std::istreambuf_iterator<char>(0),
        iostate, number.data_, number.negative_);
      if (iostate)
      {
        istr.setstate(iostate);
      }
    }
    return istr;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  std::string
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::dump() const
    /*throw (Gears::Exception)*/
  {
    assert(data_ != INVALID_FLAG_);

    Gears::OutputStackStream<TOTAL_RANK + 128> ostr;
    ostr << TOTAL_RANK << '.' << FRACTION_RANK << "(" <<
      static_cast<typename Parent::CalcType>(MAX_INTEGER_) << "," <<
      static_cast<typename Parent::CalcType>(MAX_FRACTION_) << ") " <<
      std::setfill('0') << std::setw(TOTAL_RANK) <<
      static_cast<unsigned long long>(data_);
    return ostr.str().str();
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::pack(void* buffer) const
    throw ()
  {
    assert(data_ != INVALID_FLAG_);

    memcpy(buffer, &data_, sizeof(data_));
    static_cast<unsigned char*>(buffer)[sizeof(data_)] = negative_ ? 1 : 0;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::unpack(const void* buffer)
    throw ()
  {
    memcpy(&data_, buffer, sizeof(data_));
    negative_ =
      static_cast<const unsigned char*>(buffer)[sizeof(data_)] != 0;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>&
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::negate() throw ()
  {
    assert(data_ != INVALID_FLAG_);

    negative_ = !negative_;
    return *this;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>&
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::floor(unsigned fraction)
    throw ()
  {
    assert(data_ != INVALID_FLAG_);

    if (fraction > FRACTION_RANK || fraction == FRACTION_RANK)
    {
      return *this;
    }

    Base pow = DecimalHelper::pow10<Base>(FRACTION_RANK - fraction);
    if (data_ % pow)
    {
      data_ = data_ / pow * pow;
    }

    return *this;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>&
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::ceil(unsigned fraction)
    /*throw (Gears::Exception, Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::ceil()";

    assert(data_ != INVALID_FLAG_);

    if (fraction > FRACTION_RANK || fraction == FRACTION_RANK)
    {
      return *this;
    }

    Base pow = DecimalHelper::pow10<Base>(FRACTION_RANK - fraction);
    if (data_ % pow)
    {
      Base data = (data_ / pow + 1) * pow;
      if (data == MAX_VALUE_)
      {
        Gears::ErrorStream ostr;
        ostr << FUN << ": overflow while ceiling " << str() << " on " <<
          fraction << " digit";
        throw Overflow(ostr.str());
      }
      data_ = data;
    }

    return *this;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::is_zero() const throw ()
  {
    assert(data_ != INVALID_FLAG_);

    return data_ == 0;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::is_nonnegative() const
    throw ()
  {
    assert(data_ != INVALID_FLAG_);

    return !negative_;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::is_nonpositive() const
    throw ()
  {
    assert(data_ != INVALID_FLAG_);

    return negative_;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator ==(
    const SimpleDecimal& test) const throw ()
  {
    assert(data_ != INVALID_FLAG_);
    assert(test.data_ != INVALID_FLAG_);

    return negative_ == test.negative_ ? data_ == test.data_ :
      !data_ && !test.data_;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator <(
    const SimpleDecimal& test) const throw ()
  {
    assert(data_ != INVALID_FLAG_);
    assert(test.data_ != INVALID_FLAG_);

    return negative_ ? test.negative_ ? data_ > test.data_ :
      data_ || test.data_ : !test.negative_ && data_ < test.data_;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator !=(
    const SimpleDecimal& test) const throw ()
  {
    return !operator ==(test);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator >(
    const SimpleDecimal& test) const throw ()
  {
    return test < *this;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator >=(
    const SimpleDecimal& test) const throw ()
  {
    return !(*this < test);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  bool
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator <=(
    const SimpleDecimal& test) const throw ()
  {
    return !(test < *this);
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::add(
    const SimpleDecimal& summand1, const SimpleDecimal& summand2,
    SimpleDecimal& target) /*throw (Gears::Exception, Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::add()";

    assert(summand1.data_ != INVALID_FLAG_);
    assert(summand2.data_ != INVALID_FLAG_);

    if (summand1.negative_ == summand2.negative_)
    {
      if (MAX_VALUE_ - summand1.data_ <= summand2.data_)
      {
        throw_overflow(FUN, "summing", summand1, summand2);
      }
      target.data_ = summand1.data_ + summand2.data_;
      target.negative_ = summand1.negative_;
    }
    else
    {
      if (summand1.data_ < summand2.data_)
      {
        target.data_ = summand2.data_ - summand1.data_;
        target.negative_ = summand2.negative_;
      }
      else
      {
        target.data_ = summand1.data_ - summand2.data_;
        target.negative_ = summand1.negative_;
      }
    }
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::sub(
    const SimpleDecimal& minuend, const SimpleDecimal& subtrahend,
    SimpleDecimal& target) /*throw (Gears::Exception, Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::sub()";

    assert(minuend.data_ != INVALID_FLAG_);
    assert(subtrahend.data_ != INVALID_FLAG_);

    if (minuend.negative_ != subtrahend.negative_)
    {
      if (MAX_VALUE_ - minuend.data_ <= subtrahend.data_)
      {
        throw_overflow(FUN, "subtracting",
          subtrahend, minuend);
      }
      target.data_ = minuend.data_ + subtrahend.data_;
      target.negative_ = minuend.negative_;
    }
    else
    {
      if (minuend.data_ < subtrahend.data_)
      {
        target.data_ = subtrahend.data_ - minuend.data_;
        target.negative_ = !subtrahend.negative_;
      }
      else
      {
        target.data_ = minuend.data_ - subtrahend.data_;
        target.negative_ = minuend.negative_;
      }
    }
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>&
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator +=(
    const SimpleDecimal& summand) /*throw (Gears::Exception, Overflow)*/
  {
    add(*this, summand, *this);
    return *this;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>&
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator -=(
    const SimpleDecimal& subtrahend) /*throw (Gears::Exception, Overflow)*/
  {
    sub(*this, subtrahend, *this);
    return *this;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator +(
    const SimpleDecimal& summand) const /*throw (Gears::Exception, Overflow)*/
  {
    SimpleDecimal ret;
    add(*this, summand, ret);
    return ret;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::operator -(
    const SimpleDecimal& subtrahend) const /*throw (Gears::Exception, Overflow)*/
  {
    SimpleDecimal ret;
    sub(*this, subtrahend, ret);
    return ret;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  inline
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::mul(
    const SimpleDecimal& factor1, const SimpleDecimal& factor2,
    DecimalMulRemainder dmr) /*throw (Gears::Exception, Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::mul()";

    assert(factor1.data_ != INVALID_FLAG_);
    assert(factor2.data_ != INVALID_FLAG_);

    typename Parent::CalcType res, rem;
    if (DecimalHelper::muldiv(factor1.data_, factor2.data_,
      MAX_FRACTION_, res, rem) || res >= MAX_VALUE_)
    {
      throw_overflow(FUN, "multiplying", factor1, factor2);
    }

    if (dmr != DMR_FLOOR && FRACTION_RANK &&
      (dmr == DMR_ROUND ? rem >= MAX_FRACTION_ / 2 : rem))
    {
      if (++res == MAX_VALUE_)
      {
        throw_overflow(FUN,
          "incrementing after multiplication", factor1, factor2);
      }
    }

    SimpleDecimal target;
    target.data_ = static_cast<Base>(res);
    target.negative_ = factor1.negative_ != factor2.negative_;

    return target;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::div_(
    const SimpleDecimal& dividend, const SimpleDecimal& divisor,
    SimpleDecimal& quotient, DecimalDivRemainder ddr)
    /*throw (Gears::Exception, Overflow)*/
  {
    static const char* FUN = "SimpleDecimal<>::div()";

    assert(dividend.data_ != INVALID_FLAG_);
    assert(divisor.data_ != INVALID_FLAG_);

    if (!divisor.data_)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": division by zero";
      throw Overflow(ostr.str());
    }

    typename Parent::CalcType quot, rem;
    if (DecimalHelper::muldiv(dividend.data_, MAX_FRACTION_,
      divisor.data_, quot, rem) || quot >= MAX_VALUE_)
    {
      throw_overflow(FUN, "dividing", dividend, divisor);
    }

    if (ddr == DDR_CEIL && rem)
    {
      if (++quot == MAX_VALUE_)
      {
        throw_overflow(FUN, "increment after division",
          dividend, divisor);
      }
    }

    quotient.data_ = static_cast<Base>(quot);
    quotient.negative_ = dividend.negative_ != divisor.negative_;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::div(
    const SimpleDecimal& dividend, const SimpleDecimal& divisor,
    SimpleDecimal& remainder) /*throw (Gears::Exception, Overflow)*/
  {
    SimpleDecimal quotient;
    div_(dividend, divisor, quotient, DDR_FLOOR);
    sub(dividend, mul(quotient, divisor, DMR_FLOOR), remainder);
    return quotient;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::div(
    const SimpleDecimal& dividend, const SimpleDecimal& divisor,
    DecimalDivRemainder ddr) /*throw (Gears::Exception, Overflow)*/
  {
    SimpleDecimal quotient;
    div_(dividend, divisor, quotient, ddr);
    return quotient;
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  void
  SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::
    throw_overflow(const char* func, const char* when,
      const SimpleDecimal& d1, const SimpleDecimal& d2) /*throw (Overflow)*/
  {
    Gears::ErrorStream ostr;
    ostr << func <<
      ": overflow " << when << " " << d1 << " and " << d2 << " (over " <<
      static_cast<typename Parent::CalcType>(MAX_INTEGER_) <<
      " by absolute value)";
    throw Overflow(ostr.str());
  }

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  const SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
    SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::ZERO(false, 0, 0);

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  const SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
    SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::EPSILON(
      false, FRACTION_RANK ? 0 : 1, FRACTION_RANK ? 1 : 0);

  template <typename Base, const unsigned TOTAL_RANK,
    const unsigned FRACTION_RANK>
  const SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>
    SimpleDecimal<Base, TOTAL_RANK, FRACTION_RANK>::MAXIMUM(
      false, MAX_INTEGER_ - 1, MAX_FRACTION_ - 1);

  template <typename Hash, typename Base, const unsigned TOTAL,
    const unsigned FRACTION>
  void
  hash_add(Hash& hash,
    const SimpleDecimal<Base, TOTAL, FRACTION>& key)
    throw ()
  {
    assert(key.data_ !=
      (SimpleDecimal<Base, TOTAL, FRACTION>::INVALID_FLAG_));

    hash.add(&key.data_, sizeof(key.data_));
  }
}
