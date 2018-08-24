#pragma once

#include <map>

#include "txn.h"
#include "../dbcore/sm-log-recover-impl.h"

namespace ermia {

class Engine {
public:
  Engine();
  ~Engine() {}

  void CreateTable(const char *name, const char *primary_name = nullptr);

  inline transaction *new_txn(uint64_t txn_flags, str_arena &arena, transaction *buf) {
    new (buf) transaction(txn_flags, arena);
    return buf;
  }

  inline rc_t commit_txn(transaction *t) {
    rc_t rc = t->commit();
    if (not rc_is_abort(rc)) t->~transaction();
    return rc;
  }

  inline void abort_txn(transaction *t) {
    t->abort_impl();
    t->~transaction();
  }
};

class OrderedIndex {
protected:
  IndexDescriptor *descriptor_;

public:
  OrderedIndex(std::string name, const char* primary = nullptr);
  inline IndexDescriptor *GetDescriptor() { return descriptor_; }

  class scan_callback {
   public:
    ~scan_callback() {}
    // XXX(stephentu): key is passed as (const char *, size_t) pair
    // because it really should be the string_type of the underlying
    // tree, but since ndb_ordered_index is not templated we can't
    // really do better than this for now
    virtual bool invoke(const char *keyp, size_t keylen,
                        const varstr &value) = 0;
  };

  /**
   * Get a key of length keylen. The underlying DB does not manage
   * the memory associated with key. Returns true if found, false otherwise
   */
  virtual rc_t get(transaction *t, const varstr &key, varstr &value, OID *oid = nullptr) = 0;

  /**
   * Put a key of length keylen, with mapping of length valuelen.
   * The underlying DB does not manage the memory pointed to by key or value
   * (a copy is made).
   *
   * If a record with key k exists, overwrites. Otherwise, inserts.
   *
   * If the return value is not NULL, then it points to the actual stable
   * location in memory where the value is located. Thus, [ret, ret+valuelen)
   * will be valid memory, bytewise equal to [value, value+valuelen), since the
   * implementations have immutable values for the time being. The value
   * returned is guaranteed to be valid memory until the key associated with
   * value is overriden.
   */
  virtual rc_t put(transaction *t, const varstr &key, varstr &value) = 0;

  /**
   * Insert a key of length keylen.
   *
   * If a record with key k exists, behavior is unspecified- this function
   * is only to be used when you can guarantee no such key exists (ie in loading
   *phase)
   *
   * Default implementation calls put(). See put() for meaning of return value.
   */
  virtual rc_t insert(transaction *t, const varstr &key, varstr &value,
                      OID *oid = nullptr) = 0;

  /**
   * Insert into a secondary index. Maps key to OID.
   */
  virtual rc_t insert(transaction *t, const varstr &key, OID oid) = 0;

  /**
   * Search [start_key, *end_key) if end_key is not null, otherwise
   * search [start_key, +infty)
   */
  virtual rc_t scan(transaction *t, const varstr &start_key, const varstr *end_key,
                    scan_callback &callback, str_arena *arena) = 0;
  /**
   * Search (*end_key, start_key] if end_key is not null, otherwise
   * search (-infty, start_key] (starting at start_key and traversing
   * backwards)
   */
  virtual rc_t rscan(transaction *t, const varstr &start_key, const varstr *end_key,
                     scan_callback &callback, str_arena *arena) = 0;

  /**
   * Default implementation calls put() with NULL (zero-length) value
   */
  virtual rc_t remove(transaction *t, const varstr &key) = 0;

  virtual size_t size() = 0;
  virtual std::map<std::string, uint64_t> clear() = 0;

  virtual void SetArrays() = 0;
};

// User-facing concurrent Masstree; for now also represents a table
class ConcurrentMasstreeIndex : public OrderedIndex {
  friend class sm_log_recover_impl;
  friend class sm_chkpt_mgr;

public:
  typedef concurrent_btree::string_type keystring_type;

private:
  struct SearchRangeCallback {
    SearchRangeCallback(OrderedIndex::scan_callback &upcall)
      : upcall(&upcall), return_code(rc_t{RC_FALSE}) {}
    ~SearchRangeCallback() {}

    inline bool invoke(const keystring_type &k, const varstr &v) {
      return upcall->invoke(k.data(), k.length(), v);
    }

    OrderedIndex::scan_callback *upcall;
    rc_t return_code;
  };

private:
  concurrent_btree underlying_btree;

  rc_t do_search(transaction &t, const varstr &k, varstr *out_v, OID *out_oid);

  void do_search_range_call(transaction &t, const varstr &lower,
                            const varstr *upper,
                            SearchRangeCallback &callback);

  void do_rsearch_range_call(transaction &t, const varstr &upper,
                             const varstr *lower,
                             SearchRangeCallback &callback);

  // expect_new indicates if we expect the record to not exist in the tree-
  // is just a hint that affects perf, not correctness. remove is put with
  // nullptr
  // as value.
  //
  // NOTE: both key and value are expected to be stable values already
  rc_t do_tree_put(transaction &t, const varstr *k, varstr *v, bool expect_new,
                   bool upsert, OID *inserted_oid);

  /**
   * only call when you are sure there are no concurrent modifications on the
   * tree. is neither threadsafe nor transactional
   *
   * Note that when you call unsafe_purge(), this txn_btree becomes
   * completely invalidated and un-usable. Any further operations
   * (other than calling the destructor) are undefined
   */
  std::map<std::string, uint64_t> unsafe_purge(bool dump_stats = false);

public:
  void set_arrays(IndexDescriptor *id) { underlying_btree.set_arrays(id); }
  struct purge_tree_walker : public concurrent_btree::tree_walk_callback {
    virtual void on_node_begin(
        const typename concurrent_btree::node_opaque_t *n);
    virtual void on_node_success();
    virtual void on_node_failure();

   private:
    std::vector<std::pair<typename concurrent_btree::value_type, bool> >
        spec_values;
  };

  struct txn_search_range_callback
      : public concurrent_btree::low_level_search_range_callback {
    constexpr txn_search_range_callback(transaction *t,
                                        SearchRangeCallback *caller_callback)
        : t(t), caller_callback(caller_callback) {}

    virtual void on_resp_node(const typename concurrent_btree::node_opaque_t *n,
                              uint64_t version);
    virtual bool invoke(const concurrent_btree *btr_ptr,
                        const typename concurrent_btree::string_type &k,
                        dbtuple *v,
                        const typename concurrent_btree::node_opaque_t *n,
                        uint64_t version);

   private:
    transaction *const t;
    SearchRangeCallback *const caller_callback;
  };

  ConcurrentMasstreeIndex(std::string name, const char* primary)
    : OrderedIndex(name, primary) {}

  inline rc_t get(transaction *t, const varstr &key, varstr &value, OID *oid = nullptr) override {
    return do_search(*t, key, &value, oid);
  }
  inline rc_t put(transaction *t, const varstr &key, varstr &value) override {
    return do_tree_put(*t, &key, &value, false, true, nullptr);
  }
  inline rc_t insert(transaction *t, const varstr &key, varstr &value, OID *oid = nullptr) override {
    return do_tree_put(*t, &key, &value, true, true, oid);
  }
  inline rc_t insert(transaction *t, const varstr &key, OID oid) override {
    return do_tree_put(*t, &key, (varstr *)&oid, true, false, nullptr);
  }
  inline rc_t remove(transaction *t, const varstr &key) override {
    return do_tree_put(*t, &key, nullptr, false, false, nullptr);
  }
  rc_t scan(transaction *t, const varstr &start_key, const varstr *end_key,
            scan_callback &callback, str_arena *arena) override;
  rc_t rscan(transaction *t, const varstr &start_key, const varstr *end_key,
             scan_callback &callback, str_arena *arena) override;

  inline size_t size() override { return underlying_btree.size(); }
  std::map<std::string, uint64_t> clear() override;
  inline void SetArrays() override { set_arrays(descriptor_); }
};

}  // namespace ermia
