#include <gears/CommonDecimal.hpp>

namespace Gears
{
  namespace DecimalHelper
  {
    template <>
    void
    mul<false>(uint64_t factor1, uint64_t factor2, uint64_t base,
      uint64_t& major, uint64_t& minor) noexcept
    {
      uint64_t h, l;
      __asm__ __volatile__(
        "mulq %%rdx\n"
        "divq %%rcx\n"
        : "=a" (h), "=d" (l)
        : "a" (factor1), "d" (factor2), "c" (base)
      );
      major = h;
      minor = l;
    }

    template <>
    void
    div<false>(uint64_t major, uint64_t minor, uint64_t base,
      uint64_t divisor, uint64_t& quotient, uint64_t& remainder) noexcept
    {
      uint64_t q, r;
      __asm__ __volatile__(
        "mulq %%rcx\n"
        "addq %%rsi, %%rax\n"
        "adcq $0, %%rdx\n"
        "divq %%rdi\n"
        : "=d" (r), "=a" (q)
        : "a" (major), "S" (minor), "c" (base), "D" (divisor)
      );
      quotient = q;
      remainder = r;
    }
  }
}
