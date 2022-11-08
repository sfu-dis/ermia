#ifndef UTIL_HASH_H_
#define UTIL_HASH_H_
/*
* A collection of hash functions
*/

// #include <bits/hash_bytes.h>
#include <stddef.h>
#include <functional>

namespace {
inline std::size_t unaligned_load(const char *p) {
  std::size_t result;
  __builtin_memcpy(&result, p, sizeof(result));
  return result;
}

#if __SIZEOF_SIZE_T__ == 8
// Loads n bytes, where 1 <= n < 8.
inline std::size_t load_bytes(const char *p, int n) {
  std::size_t result = 0;
  --n;
  do
    result = (result << 8) + static_cast<unsigned char>(p[n]);
  while (--n >= 0);
  return result;
}

inline std::size_t shift_mix(std::size_t v) { return v ^ (v >> 47); }
#endif
}  // namespace

inline size_t Hash_bytes(const void *ptr, size_t len, size_t seed) {
  static const size_t mul = (0xc6a4a793UL << 32UL) + 0x5bd1e995UL;
  const char *const buf = static_cast<const char *>(ptr);

  // Remove the bytes not divisible by the sizeof(size_t).  This
  // allows the main loop to process the data as 64-bit integers.
  const int len_aligned = len & ~0x7;
  const char *const end = buf + len_aligned;
  size_t hash = seed ^ (len * mul);
  for (const char *p = buf; p != end; p += 8) {
    const size_t data = shift_mix(unaligned_load(p) * mul) * mul;
    hash ^= data;
    hash *= mul;
  }
  if ((len & 0x7) != 0) {
    const size_t data = load_bytes(end, len & 0x7);
    hash ^= data;
    hash *= mul;
  }
  hash = shift_mix(hash) * mul;
  hash = shift_mix(hash);
  return hash;
}

inline size_t standard(const void *_ptr, size_t _len,
                       size_t _seed = static_cast<size_t>(0xc70f6907UL)) {
  // return std::_Hash_bytes(_ptr, _len, _seed);
  return Hash_bytes(_ptr, _len, _seed);
}

// JENKINS HASH FUNCTION
inline size_t jenkins(const void *_ptr, size_t _len,
                      size_t _seed = 0xc70f6907UL) {
  size_t i = 0;
  size_t hash = 0;
  const char *key = static_cast<const char *>(_ptr);
  while (i != _len) {
    hash += key[i++];
    hash += hash << (10);
    hash ^= hash >> (6);
  }
  hash += hash << (3);
  hash ^= hash >> (11);
  hash += hash << (15);
  return hash;
}

//-----------------------------------------------------------------------------
// MurmurHash2, by Austin Appleby

// Note - This code makes a few assumptions about how your machine behaves -

// 1. We can read a 4-byte value from any address without crashing
// 2. sizeof(int) == 4

// And it has a few limitations -

// 1. It will not work incrementally.
// 2. It will not produce the same results on little-endian and big-endian
//    machines.
inline size_t murmur2(const void *key, size_t len, size_t seed = 0xc70f6907UL) {
  // 'm' and 'r' are mixing constants generated offline.
  // They're not really 'magic', they just happen to work well.

  const unsigned int m = 0x5bd1e995;
  const int r = 24;

  // Initialize the hash to a 'random' value

  unsigned int h = seed ^ len;

  // Mix 4 bytes at a time into the hash

  const unsigned char *data = (const unsigned char *)key;

  while (len >= 4) {
    unsigned int k = *(unsigned int *)data;

    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;

    data += 4;
    len -= 4;
  }

  // Handle the last few bytes of the input array

  switch (len) {
    case 3:
      h ^= data[2] << 16;
    case 2:
      h ^= data[1] << 8;
    case 1:
      h ^= data[0];
      h *= m;
  };

  // Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
}

#define NUMBER64_1 11400714785074694791ULL
#define NUMBER64_2 14029467366897019727ULL
#define NUMBER64_3 1609587929392839161ULL
#define NUMBER64_4 9650029242287828579ULL
#define NUMBER64_5 2870177450012600261ULL

#define hash_get64bits(x) hash_read64_align(x, align)
#define hash_get32bits(x) hash_read32_align(x, align)
#define shifting_hash(x, r) ((x << r) | (x >> (64 - r)))
#define TO64(x) (((U64_INT *)(x))->v)
#define TO32(x) (((U32_INT *)(x))->v)

typedef struct U64_INT {
  uint64_t v;
} U64_INT;

typedef struct U32_INT {
  uint32_t v;
} U32_INT;

uint64_t hash_read64_align(const void *ptr, uint32_t align);

uint32_t hash_read32_align(const void *ptr, uint32_t align);

uint64_t hash_compute(const void *input, uint64_t length, uint64_t seed,
                      uint32_t align);

uint64_t xxhash(const void *data, size_t length, size_t seed);

static size_t (*hash_funcs[4])(const void *key, size_t len, size_t seed) = {
    standard, murmur2, jenkins, xxhash};

inline size_t h(const void *key, size_t len, size_t seed = 0xc70697UL) {
  return hash_funcs[0](key, len, seed);
}

inline size_t h2(const void *key, size_t len, size_t seed = 0xc70697UL) {
  return hash_funcs[1](key, len, seed);
}

#endif  // UTIL_HASH_H_
