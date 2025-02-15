#ifndef GEARS_RAND_HPP_
#define GEARS_RAND_HPP_

#include <cstdint>

namespace Gears
{
  /**
   * Thread safe service for random numbers generation.
   * Based on ISAAC generator with /dev/urandom seed.
   * @return random number in [0..RAND_MAX] range
   */
  uint32_t
  safe_rand() noexcept;

  /**
   * Give uniform distribution in range [0..max_boundary-1].
   * Thread-safe.
   * @param max_boundary maximum random value.
   * @return uniformly distributed positive random variable in
   * [0, max_boundary - 1] range.
   */
  inline
  uint32_t
  safe_rand(uint32_t max_boundary) noexcept
  {
    return static_cast<uint32_t>(static_cast<double>(max_boundary) *
      safe_rand() / 2147483648.0);
  }

  /**
   * General method give uniform distribution in range.
   * Thread-safe.
   * @param min_boundary minimum random value
   * @param max_boundary maximum random value
   * @return uniformly distributed positive random variable in
   * [min_boundary, max_boundary] range.
   */
  inline
  uint32_t
  safe_rand(uint32_t min_boundary, uint32_t max_boundary) noexcept
  {
    return min_boundary + safe_rand(max_boundary - min_boundary + 1);
  }
}

#endif
