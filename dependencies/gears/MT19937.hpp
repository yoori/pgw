#ifndef GENERICS_MT19937_HPP_
#define GENERICS_MT19937_HPP_

#include <cstdint>

#include <unistd.h>
#include <fcntl.h>

#include <gears/Time.hpp>
#include <gears/Uncopyable.hpp>

namespace Gears
{
  /**
   * Mersenne-Twister random number generation with period of 2^19937-1
   * Not thread safe
   */
  class MT19937 : private Uncopyable
  {
  public:
    static const size_t STATE_SIZE = 624;

    /**
     * Up limit for random numbers range.
     * This generator range is [0, RAND_MAXIMUM]
     */
    static const uint32_t RAND_MAXIMUM = ~static_cast<uint32_t>(0);

    /**
     * Constructor
     * Uses /dev/urandom for initialization
     */
    MT19937() noexcept;
    /**
     * Constructor
     * @param value initial seed number
     */
    explicit
    MT19937(const uint32_t value) noexcept;
    /**
     * Constructor
     * @param value pointer to data for initial seed
     * @param size data size
     */
    explicit
    MT19937(const uint32_t* value, size_t size = STATE_SIZE) noexcept;

    /**
     * Initializes object
     * Uses /dev/urandom for initialization
     */
    void
    seed() noexcept;
    /**
     * Initializes object
     * @param value initial seed number
     */
    void
    seed(uint32_t value) noexcept;
    /**
     * Initializes object
     * @param value pointer to data for initial seed
     * @param size data size
     */
    void
    seed(const uint32_t* value, size_t size = STATE_SIZE) noexcept;

    /**
     * Creates next random number in the sequence
     * @return random number in [0..2^32-1] range
     */
    uint32_t
    rand() noexcept;

  protected:
    /**
     * Initializes state
     * @param value initial seed number
     */
    void
    initialize(uint32_t value) noexcept;

    /**
     * Refreshes state after each pass
     */
    void
    reinit() noexcept;

  private:
    uint32_t State_[STATE_SIZE];
    const uint32_t* Next_;
    int Left_;
  };
}

//
// INLINES
//

namespace Gears
{
  inline
  MT19937::MT19937() noexcept
  {
    seed();
  }

  inline
  MT19937::MT19937(const uint32_t value) noexcept
  {
    seed(value);
  }

  inline
  MT19937::MT19937(const uint32_t* value, size_t size) noexcept
  {
    seed(value, size);
  }

  inline
  uint32_t
  MT19937::rand() noexcept
  {
    if (!Left_)
    {
      reinit();
    }
    Left_--;

    uint32_t res = *Next_++;
    res ^= (res >> 11);
    res ^= (res << 7) & 0x9D2C5680ul;
    res ^= (res << 15) & 0xEFC60000ul;
    return (res ^ (res >> 18));
  }

  namespace MT19937Helper
  {
    inline
    uint32_t
    MT19937_hash(const void* data, size_t size) noexcept
    {
      const uint8_t* ptr = static_cast<const uint8_t*>(data);
      uint32_t value = 0;
      while (size-- > 0)
      {
        value *= 257;
        value += *ptr++;
      }
      return value;
    }

    template <typename T>
    inline
    uint32_t
    MT19937_hash(const T data) noexcept
    {
      return MT19937_hash(&data, sizeof(data));
    }

    inline
    uint32_t
    MT19937_mix(const uint32_t m, const uint32_t s0,
      const uint32_t s1) noexcept
    {
      return m ^
        (((s0 & 0x80000000ul) | (s1 & 0x7FFFFFFFul)) >> 1) ^
        (-(s1 & 0x00000001ul) & 0x9908B0DFul);
    }
  }

  inline
  void
  MT19937::reinit() noexcept
  {
    static const size_t PERIOD_LENGTH = 397;

    uint32_t* p = State_;
    for (int i = STATE_SIZE - PERIOD_LENGTH; i--; ++p)
    {
      *p = MT19937Helper::MT19937_mix(p[PERIOD_LENGTH], p[0], p[1]);
    }
    for (int i = PERIOD_LENGTH; --i; ++p)
    {
      *p = MT19937Helper::MT19937_mix(p[PERIOD_LENGTH - STATE_SIZE],
        p[0], p[1]);
    }
    *p = MT19937Helper::MT19937_mix(p[PERIOD_LENGTH - STATE_SIZE],
      p[0], State_[0]);

    Left_ = STATE_SIZE;
    Next_ = State_;
  }

  inline
  void
  MT19937::seed() noexcept
  {
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom >= 0)
    {
      uint32_t value[STATE_SIZE];
      bool success;
      for (;;)
      {
        ssize_t res = read(urandom, value, sizeof(value));
        success = res == sizeof(value);
        if (res <= 0 || success)
        {
          break;
        }
      }
      close(urandom);
      if (success)
      {
        seed(value, STATE_SIZE);
        return;
      }
    }

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    seed(
      MT19937Helper::MT19937_hash(hostname, sizeof(hostname)) ^
      MT19937Helper::MT19937_hash(Time::get_time_of_day()) ^
      MT19937Helper::MT19937_hash(clock()) ^
      MT19937Helper::MT19937_hash(getpid()));
  }

  inline
  void
  MT19937::seed(uint32_t value) noexcept
  {
    initialize(value);
    reinit();
  }

  inline
  void
  MT19937::seed(const uint32_t* value, size_t size) noexcept
  {
    initialize(0x21414B53ul);
    size_t i = 1;
    uint32_t j = 0;
    for (size_t k = (STATE_SIZE > size ? STATE_SIZE : size);
      k; --k)
    {
      State_[i] ^= (State_[i - 1] ^ (State_[i - 1] >> 30)) * 1664525ul;
      State_[i] += value[j] + j;
      if (++i >= STATE_SIZE)
      {
        State_[0] = State_[STATE_SIZE - 1];
        i = 1;
      }
      if (++j >= size)
      {
        j = 0;
      }
    }
    for (size_t k = STATE_SIZE - 1; k; --k)
    {
      State_[i] ^= (State_[i - 1] ^ (State_[i - 1] >> 30)) * 1566083941ul;
      State_[i] -= i;
      if (++i >= STATE_SIZE)
      {
        State_[0] = State_[STATE_SIZE - 1];
        i = 1;
      }
    }
    State_[0] = 0x80000000ul;
    reinit();
  }

  inline
  void
  MT19937::initialize(uint32_t value) noexcept
  {
    uint32_t* s = State_;
    *s++ = value;
    for (size_t i = 1; i < STATE_SIZE; ++i)
    {
      value = 1812433253ul * (value ^ (value >> 30)) + i;
      *s++ = value;
    }
  }
}

#endif
