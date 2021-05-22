#pragma once

#include "../dbcore/sm-log-recover-impl.h"
#include "txn.h"
#include "../benchmarks/record/encoder.h"
#include "../dbcore/sm-dir-it.h"
#include "ermia_internal.h"

namespace ermia {

class Table;

class Engine {
private:
  void LogIndexCreation(bool primary, FID table_fid, FID index_fid, const std::string &index_name);
  void CreateIndex(const char *table_name, const std::string &index_name, bool is_primary, bool is_unique = true);

public:
  Engine();
  ~Engine() {}

  // All supported index types
  static const uint16_t kIndexConcurrentMasstree = 0x1;

  // Create a table without any index (at least yet)
  TableDescriptor *CreateTable(const char *name);

  // Create the primary index for a table
  inline void CreateMasstreePrimaryIndex(const char *table_name, const std::string &index_name) {
    CreateIndex(table_name, index_name, true);
  }

  // Create a secondary masstree index
  inline void CreateMasstreeSecondaryIndex(const char *table_name, const std::string &index_name, bool is_unique = true) {
    CreateIndex(table_name, index_name, false, is_unique);
  }

  inline transaction *NewTransaction(uint64_t txn_flags, str_arena &arena, transaction *buf) {
    // Reset the arena here - can't rely on the benchmark/user code to do it
    arena.reset();
    new (buf) transaction(txn_flags, arena);
    return buf;
  }

  inline rc_t Commit(transaction *t) {
    rc_t rc = t->commit();
    if (!rc.IsAbort()) {
      t->~transaction();
    }
    return rc;
  }

  inline uint64_t GetLSN(transaction *t) {
    return t->get_clsn();
  }

  inline uintptr_t PreCommit(transaction *t) {
    return t->pre_commit().offset();
  }

  inline void Abort(transaction *t) {
    t->Abort();
    t->~transaction();
  }
};

// User-facing table abstraction, operates on OIDs only
class Table {
private:
  TableDescriptor *td;

public:
  rc_t Insert(transaction &t, varstr *value, OID *out_oid);
  rc_t Update(transaction &t, OID oid, varstr &value);
  rc_t Read(transaction &t, OID oid, varstr *out_value);
  rc_t Remove(transaction &t, OID oid);
};

// User-facing concurrent Masstree
class ConcurrentMasstreeIndex : public OrderedIndex {
  friend struct sm_log_recover_impl;
  friend class sm_chkpt_mgr;

private:
  ConcurrentMasstree masstree_;

  struct SearchRangeCallback {
    SearchRangeCallback(OrderedIndex::ScanCallback &upcall)
        : upcall(&upcall), return_code(rc_t{RC_FALSE}) {}
    ~SearchRangeCallback() {}

    inline bool Invoke(const ConcurrentMasstree::string_type &k,
                       const varstr &v) {
      // We've reached the limit, stop the Invoke now
      if (upcall->limit == 0) {
        return false;
      }
      auto ret =  upcall->Invoke(k.data(), k.length(), v);
      upcall->limit = upcall->limit - 1;
      return ret;
    }

    OrderedIndex::ScanCallback *upcall;
    rc_t return_code;
  };

  struct XctSearchRangeCallback
      : public ConcurrentMasstree::low_level_search_range_callback {
    XctSearchRangeCallback(transaction *t, SearchRangeCallback *caller_callback)
        : t(t), caller_callback(caller_callback) {}

    virtual void
    on_resp_node(const typename ConcurrentMasstree::node_opaque_t *n,
                 uint64_t version);
    virtual bool invoke(const ConcurrentMasstree *btr_ptr,
                        const typename ConcurrentMasstree::string_type &k,
                        dbtuple *v,
                        const typename ConcurrentMasstree::node_opaque_t *n,
                        uint64_t version);

  private:
    transaction *const t;
    SearchRangeCallback *const caller_callback;
  };

  struct PurgeTreeWalker : public ConcurrentMasstree::tree_walk_callback {
    virtual void
    on_node_begin(const typename ConcurrentMasstree::node_opaque_t *n);
    virtual void on_node_success();
    virtual void on_node_failure();

  private:
    std::vector<std::pair<typename ConcurrentMasstree::value_type, bool>>
        spec_values;
  };

  static rc_t DoNodeRead(transaction *t,
                         const ConcurrentMasstree::node_opaque_t *node,
                         uint64_t version);

public:
  ConcurrentMasstreeIndex(const char *table_name, bool primary) : OrderedIndex(table_name, primary) {}

  ConcurrentMasstree &GetMasstree() { return masstree_; }

  inline void *GetTable() override { return masstree_.get_table(); }

  virtual void GetRecord(transaction *t, rc_t &rc, const varstr &key, varstr &value,
                         OID *out_oid = nullptr) override;
  virtual void GetRecordMulti(transaction *t, rc_t &rc, const varstr &key, std::vector<varstr> &value,
                              std::vector<OID> *oids = nullptr);
  virtual DirIterator *GetRecordMultiIt(transaction *t, rc_t &rc, const varstr &key);

  rc_t UpdateRecord(transaction *t, const varstr &key, varstr &value) override;
  rc_t InsertRecord(transaction *t, const varstr &key, varstr &value, OID *out_oid = nullptr) override;
  rc_t RemoveRecord(transaction *t, const varstr &key) override;
  bool InsertOID(transaction *t, const varstr &key, OID oid) override;

  rc_t Scan(transaction *t, const varstr &start_key, const varstr *end_key,
                     ScanCallback &callback, str_arena *arena) override;
  rc_t ReverseScan(transaction *t, const varstr &start_key,
                            const varstr *end_key, ScanCallback &callback,
                            str_arena *arena) override;

  inline size_t Size() override { return masstree_.size(); }
  std::map<std::string, uint64_t> Clear() override;
  inline void SetArrays(bool primary) override { masstree_.set_arrays(table_descriptor, primary); }

  inline void
  GetOID(const varstr &key, rc_t &rc, TXN::xid_context *xc, OID &out_oid,
         ConcurrentMasstree::versioned_node_t *out_sinfo = nullptr) override {
    bool found = masstree_.search(key, out_oid, xc->begin_epoch, out_sinfo);
    volatile_write(rc._val, found ? RC_TRUE : RC_FALSE);
  }

private:
  bool InsertIfAbsent(transaction *t, const varstr &key, OID oid) override;
  bool InsertToDir(transaction *t, const varstr &key, OID oid);
};
} // namespace ermia
