#pragma once
#include <sys/stat.h>
#include <x86intrin.h>
#include <atomic>
#include <cstdint>

#define IS_POWER_OF_TWO(x) (x && (x & (x - 1)) == 0)

inline uint64_t Murmur3_64(uint64_t h)
{
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccd;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53;
  h ^= h >> 33;
  return h;
}

template <typename T>
T CompareExchange64(T *destination, T new_value, T comparand)
{
  static_assert(sizeof(T) == 8,
                "CompareExchange64 only works on 64 bit values");
  ::__atomic_compare_exchange_n(destination, &comparand, new_value, false,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return comparand;
}

namespace very_pm
{

  static const constexpr bool kUseCLWB = true;

  static const constexpr uint64_t CREATE_MODE_RW = (S_IWUSR | S_IRUSR);

  static const constexpr uint64_t kPMDK_PADDING = 48;

  static bool FileExists(const char *pool_path)
  {
    struct stat buffer;
    return (stat(pool_path, &buffer) == 0);
  }

  static const constexpr uint64_t kCacheLineSize = 64;

  static void flush(void *addr)
  {
#if CASCADE_LAKE == 1
    _mm_clwb(addr);
#else
    _mm_clflush(addr);
#endif
  }

  static void fence() { _mm_mfence(); }

  template <typename T>
  T CompareExchange64(T *destination, T new_value, T comparand)
  {
    static_assert(sizeof(T) == 8,
                  "CompareExchange64 only works on 64 bit values");
    ::__atomic_compare_exchange_n(destination, &comparand, new_value, false,
                                  __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return comparand;
  }
} // namespace very_pm
