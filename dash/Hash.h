
// Copyright (c) Simon Fraser University & The Chinese University of Hong Kong.
// All rights reserved. Licensed under the MIT license.
#ifndef HASH_INTERFACE_H_
#define HASH_INTERFACE_H_

#include "util/pair.h"

/*
 * Parent function of all hash indexes
 * Used to define the interface of the hash indexes
 */
namespace ermia
{
  template <class K, class V>
  class Hash
  {
  public:
    Hash(void) = default;
    ~Hash(void) = default;
    /*0 means success insert, -1 means this key already exist, directory return*/
    virtual int Insert(K, V) = 0;
    virtual int Insert(K, V, bool) = 0;

    virtual void bootRestore(){

    };
    virtual void reportRestore(){

    };
    virtual bool Delete(K) = 0;
    virtual bool Delete(K, bool) = 0;
    virtual bool Get(K, V *) = 0;
    virtual bool Get(K key, V *, bool is_in_epoch) = 0;
    virtual void getNumber() = 0;
  };
}
#endif // _HASH_INTERFACE_H_
