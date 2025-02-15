#include <gears/Lock.hpp>
#include <gears/ISAAC.hpp>
#include <gears/MT19937.hpp>

namespace Gears
{
  namespace
  {
    Gears::Mutex mutex;
    ISAAC generator;
  }

  const size_t MT19937::STATE_SIZE;
  const uint32_t MT19937::RAND_MAXIMUM;

  const uint32_t ISAAC::RAND_MAXIMUM;
  const size_t ISAAC::SIZE;

  uint32_t
  safe_rand() noexcept
  {
    Gears::Mutex::WriteGuard lock(mutex);
    return generator.rand() >> 1;
  }
}
