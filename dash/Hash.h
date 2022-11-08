
// Copyright (c) Simon Fraser University & The Chinese University of Hong Kong. All rights reserved.
// Licensed under the MIT license.
#ifndef HASH_INTERFACE_H_
#define HASH_INTERFACE_H_

#include "util/pair.h"
#ifdef PMEM
#include <libpmemobj.h>
#endif
#include "../dbcore/sm-coroutine.h"

/*
* Parent function of all hash indexes
* Used to define the interface of the hash indexes
*/
namespace dash {

template <class K, class V>
class Hash {
 public:
  Hash(void) = default;
  ~Hash(void) = default;

  virtual PROMISE(bool) Insert(K, V) = 0;
  virtual PROMISE(bool) Delete(K) = 0;
  virtual PROMISE(bool) Get(K, V *) = 0;

  PROMISE(bool) Insert(K, V, bool);
  PROMISE(bool) Delete(K, bool);
  PROMISE(bool) Get(K key, V *, bool);

  virtual void getNumber() = 0;

  static_assert(std::is_pointer_v<V>, "Value type has to be a pointer!");
};

template <class K, class V>
PROMISE(bool) Hash<K, V>::Insert(K key, V value, bool is_in_epoch) {
  if (!is_in_epoch) {
    // auto epoch_guard = Allocator::AquireEpochGuard();
    return Insert(key, value);
  }
  return Insert(key, value);
}

template <class K, class V>
PROMISE(bool) Hash<K, V>::Delete(K key, bool is_in_epoch) {
  if (!is_in_epoch) {
    // auto epoch_guard = Allocator::AquireEpochGuard();
    return Delete(key);
  }
  return Delete(key);
}

template <class K, class V>
PROMISE(bool) Hash<K, V>::Get(K key, V *value, bool is_in_epoch) {
  if (!is_in_epoch) {
    // auto epoch_guard = Allocator::AquireEpochGuard();
    return Get(key, value);
  }
  return Get(key, value);
}

} // namespace dash

#endif  // _HASH_INTERFACE_H_
