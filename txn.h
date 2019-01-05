#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <vector>
#include <string>
#include <utility>
#include <stdexcept>
#include <limits>
#include <unordered_set>

#include "dbcore/xid.h"
#include "dbcore/sm-config.h"
#include "dbcore/sm-oid.h"
#include "dbcore/sm-log.h"
#include "dbcore/sm-object.h"
#include "dbcore/sm-rc.h"
#include "masstree_btree.h"
#include "macros.h"
#include "str_arena.h"
#include "tuple.h"

#include <sparsehash/dense_hash_map>
using google::dense_hash_map;

namespace ermia {

// A write-set entry is essentially a pointer to the OID array entry
// begin updated. The write-set is naturally de-duplicated: repetitive
// updates will leave only one entry by the first update. Dereferencing
// the entry pointer results a fat_ptr to the new object.
struct write_record_t {
  fat_ptr *entry;
  write_record_t(fat_ptr *entry) : entry(entry) {}
  write_record_t() : entry(nullptr) {}
  inline Object *get_object() { return (Object *)entry->offset(); }
};

struct write_set_t {
  static const uint32_t kMaxEntries = 256;
  uint32_t num_entries;
  write_record_t entries[kMaxEntries];
  write_set_t() : num_entries(0) {}
  inline void emplace_back(fat_ptr *oe) {
    ALWAYS_ASSERT(num_entries < kMaxEntries);
    new (&entries[num_entries]) write_record_t(oe);
    ++num_entries;
    ASSERT(entries[num_entries - 1].entry == oe);
  }
  inline uint32_t size() { return num_entries; }
  inline void clear() { num_entries = 0; }
  inline write_record_t &operator[](uint32_t idx) { return entries[idx]; }
};

// forward decl
class base_txn_btree;

class transaction {
  friend class base_txn_btree;
  friend class sm_oid_mgr;

 public:
  typedef TXN::txn_state txn_state;

#if defined(SSN) || defined(SSI) || defined(MVOCC)
  typedef std::vector<dbtuple *> read_set_t;
#endif

  enum {
    // use the low-level scan protocol for checking scan consistency,
    // instead of keeping track of absent ranges
    TXN_FLAG_LOW_LEVEL_SCAN = 0x1,

    // true to mark a read-only transaction- if a txn marked read-only
    // does a write, it is aborted. SSN uses it to implement to safesnap.
    // No bookeeping is done with SSN if this is enable for a tx.
    TXN_FLAG_READ_ONLY = 0x2,

    TXN_FLAG_READ_MOSTLY = 0x3,

    // A redo transaction running on a backup server using command logging.
    TXN_FLAG_CMD_REDO = 0x4,
  };

  inline bool is_read_mostly() { return flags & TXN_FLAG_READ_MOSTLY; }
  inline bool is_read_only() { return flags & TXN_FLAG_READ_ONLY; }

 protected:
  inline txn_state state() const { return xc->state; }

  // only fires during invariant checking
  inline void ensure_active() {
    volatile_write(xc->state, TXN::TXN_ACTIVE);
    ASSERT(state() == TXN::TXN_ACTIVE);
  }
  // the absent set is a mapping from (btree_node -> version_number).
  struct absent_record_t {
    uint64_t version;
  };
  typedef dense_hash_map<const concurrent_btree::node_opaque_t *,
                         absent_record_t> absent_set_map;
  absent_set_map absent_set;

 public:
  transaction(uint64_t flags, str_arena &sa);
  ~transaction();
  void initialize_read_write();

  rc_t commit();
#ifdef SSN
  rc_t parallel_ssn_commit();
  rc_t ssn_read(dbtuple *tuple);
#elif defined SSI
  rc_t parallel_ssi_commit();
  rc_t ssi_read(dbtuple *tuple);
#elif defined MVOCC
  rc_t mvocc_commit();
  rc_t mvocc_read(dbtuple *tuple);
#else
  rc_t si_commit();
#endif

  bool check_phantom();
  void abort_impl();

 protected:
  bool try_insert_new_tuple(concurrent_btree *btr, const varstr *key,
                            varstr *value, OID *inserted_oid);

  // reads the contents of tuple into v
  // within this transaction context
  rc_t do_tuple_read(dbtuple *tuple, varstr *out_v);
  rc_t do_node_read(const typename concurrent_btree::node_opaque_t *n,
                    uint64_t version);

 public:
  // expected public overrides

  inline str_arena &string_allocator() { return *sa; }

  inline void add_to_write_set(fat_ptr *entry) {
#ifndef NDEBUG
    for (uint32_t i = 0; i < write_set.size(); ++i) {
      auto &w = write_set[i];
      ASSERT(w.entry);
      ASSERT(w.entry != entry);
    }
#endif
    write_set.emplace_back(entry);
  }

 protected:
  const uint64_t flags;
  XID xid;
  TXN::xid_context *xc;
  sm_tx_log *log;
  str_arena *sa;
  write_set_t &write_set;
#if defined(SSN) || defined(SSI) || defined(MVOCC)
  read_set_t *read_set;
#endif
};

}  // namespace ermia
