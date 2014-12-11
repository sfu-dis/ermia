#ifndef _NDB_TXN_IMPL_H_
#define _NDB_TXN_IMPL_H_

#include "txn.h"
#include "lockguard.h"

#include "object.h"
#include "dbcore/sm-common.h"

using namespace TXN;

// base definitions

template <template <typename> class Protocol, typename Traits>
transaction<Protocol, Traits>::transaction(uint64_t flags, string_allocator_type &sa)
  : transaction_base(flags), sa(&sa)
{
  RA::epoch_enter();
#ifdef BTREE_LOCK_OWNERSHIP_CHECKING
  concurrent_btree::NodeLockRegionBegin();
#endif
  xid_context *xc = xid_get_context(xid);
  RCU::rcu_enter();
  xc->begin = logger->cur_lsn();
  RCU::rcu_enter();
  xc->end = INVALID_LSN;
  xc->state = TXN_EMBRYO;
}

template <template <typename> class Protocol, typename Traits>
transaction<Protocol, Traits>::~transaction()
{
  // transaction shouldn't fall out of scope w/o resolution
  // resolution means TXN_EMBRYO, TXN_CMMTD, and TXN_ABRTD
  INVARIANT(state() != TXN_ACTIVE && state() != TXN_COMMITTING);

#ifdef BTREE_LOCK_OWNERSHIP_CHECKING
  concurrent_btree::AssertAllNodeLocksReleased();
#endif
  write_set.clear();
  read_set.clear();
  RA::epoch_exit();
}

template <template <typename> class Protocol, typename Traits>
void
transaction<Protocol, Traits>::signal_abort(abort_reason reason)
{
  abort_trap(reason);
  volatile_write(xid_get_context(xid)->state, TXN_ABRTD);
  throw transaction_abort_exception(reason);
}
  
template <template <typename> class Protocol, typename Traits>
void
transaction<Protocol, Traits>::abort_impl()
{
  INVARIANT(state() == TXN_ABRTD);

  for (auto &w : write_set) {
    dbtuple *tuple = w.first;
    ASSERT(tuple);
    ASSERT(XID::from_ptr(tuple->clsn) == xid);
    w.second->unlink_tuple(tuple->oid, (typename concurrent_btree::value_type)tuple);
  }

  for (auto &r : read_set) {
    dbtuple *tuple = r.first;
    ASSERT(tuple == reinterpret_cast<dbtuple *>(r.second.btr->fetch_committed_version_at(tuple->oid, xid, LSN::from_ptr(tuple->clsn))));
    // remove myself from reader list
    readers_reg.deregister_tx(tuple->rlist, r.second.reader_pos);
  }

  // log discard
  RCU::rcu_enter();
  log->pre_commit();
  log->discard();
  RCU::rcu_exit();

  // now safe to free XID
  xid_free(xid);
}

namespace {
  inline const char *
  transaction_state_to_cstr(txn_state state)
  {
    switch (state) {
    case TXN_EMBRYO: return "TXN_EMBRYO";
    case TXN_ACTIVE: return "TXN_ACTIVE";
    case TXN_ABRTD: return "TXN_ABRTD";
    case TXN_CMMTD: return "TXN_CMMTD";
    case TXN_COMMITTING: return "TXN_COMMITTING";
    }
    ALWAYS_ASSERT(false);
    return 0;
  }

  inline std::string
  transaction_flags_to_str(uint64_t flags)
  {
    bool first = true;
    std::ostringstream oss;
    if (flags & transaction_base::TXN_FLAG_LOW_LEVEL_SCAN) {
      oss << "TXN_FLAG_LOW_LEVEL_SCAN";
      first = false;
    }
    if (flags & transaction_base::TXN_FLAG_READ_ONLY) {
      if (first)
        oss << "TXN_FLAG_READ_ONLY";
      else
        oss << " | TXN_FLAG_READ_ONLY";
      first = false;
    }
    return oss.str();
  }
}

template <template <typename> class Protocol, typename Traits>
void
transaction<Protocol, Traits>::dump_debug_info() const
{
  std::cerr << "Transaction (obj=" << util::hexify(this) << ") -- state "
       << transaction_state_to_cstr(state()) << std::endl;
  std::cerr << "  Abort Reason: " << AbortReasonStr(reason) << std::endl;
  std::cerr << "  Flags: " << transaction_flags_to_str(flags) << std::endl;
}

template <template <typename> class Protocol, typename Traits>
void
transaction<Protocol, Traits>::commit()
{
#ifdef USE_PARALLEL_SSN
  ssn_parallel_si_commit();
#else
  si_commit();
#endif
}

#ifdef USE_PARALLEL_SSN
template <template <typename> class Protocol, typename Traits>
void
transaction<Protocol, Traits>::ssn_parallel_si_commit()
{
  xid_context* xc = xid_get_context(xid);

  PERF_DECL(
      static std::string probe0_name(
        std::string(__PRETTY_FUNCTION__) + std::string(":total:")));
  ANON_REGION(probe0_name.c_str(), &transaction_base::g_txn_commit_probe0_cg);

  switch (state()) {
  case TXN_EMBRYO:
  case TXN_ACTIVE:
    xc->state = TXN_COMMITTING;
    break;
  case TXN_CMMTD:
  case TXN_COMMITTING:
  case TXN_ABRTD:
    ALWAYS_ASSERT(false);
  }

  INVARIANT(log);
  // get clsn, abort if failed
  RCU::rcu_enter();
  xc->end = log->pre_commit();
  LSN clsn = xc->end;
  if (xc->end == INVALID_LSN)
    signal_abort(ABORT_REASON_INTERNAL);

  // find out my largest predecessor (\eta) and smallest sucessor (\pi)
  // for reads, see if sb. has written the tuples - look at sucessor lsn
  // for writes, see if sb. has read the tuples - look at access lsn

  for (auto &w : write_set) {
    dbtuple *tuple = w.first;
    object *obj = (object *)((char *)tuple - sizeof(object));
    if (obj->_next == NULL_PTR) // this is an insert
      continue;

    // go to the committed version I (am about to) overwrote for the reader list
    dbtuple *overwritten_tuple = (dbtuple *)((object *)obj->_next.offset())->payload();
    ASSERT(overwritten_tuple->clsn.asi_type() == fat_ptr::ASI_LOG);
    ASSERT(overwritten_tuple->oid == tuple->oid);

    // need access stamp , i.e., who read this version that I'm trying to overwrite?
    //XID *reader_xids = readers_reg.get_xid_list((uintptr_t)overwritten_tuple);
    if (not overwritten_tuple->rlist)
      continue;
    XID *reader_xids = overwritten_tuple->rlist->xids;
    ASSERT(reader_xids);
    if (overwritten_tuple->rlist->bitmap == readers_registry::bitmap_t(1 << XIDS_PER_READER_KEY))
      continue;
    for (auto i = 0; i < XIDS_PER_READER_KEY; i++) {
      XID xid = volatile_read(reader_xids[i]);
      if (not xid._val)
        continue;
      xid_context *reader_xc = xid_get_context(xid);
      ASSERT(reader_xc->owner == xid);
      LSN reader_end = volatile_read(reader_xc->end);
      // reader committed
      if (reader_end != INVALID_LSN and reader_end < clsn and wait_for_commit_result(reader_xc)) {
        if (xc->pred < reader_end)
          xc->pred = reader_end;
      }
    }
  }

  for (auto &r : read_set) {
    dbtuple *tuple = r.first;
    // so tuple should be the committed version I read
    ASSERT(tuple->clsn.asi_type() == fat_ptr::ASI_LOG);
    dbtuple *overwriter_tuple = (dbtuple *)r.second.btr->fetch_overwriter(tuple->oid,
                                                        LSN::from_ptr(tuple->clsn));
    if (not overwriter_tuple)
      continue;

  try_get_sucessor:
    // read tuple->slsn to a local variable before doing anything relying on it,
    // it might be changed any time...
    fat_ptr sucessor_clsn = volatile_read(overwriter_tuple->clsn);

    // overwriter in progress?
    if (sucessor_clsn.asi_type() == fat_ptr::ASI_XID) {
      xid_context *sucessor_xc = xid_get_context(XID::from_ptr(sucessor_clsn));
      if (sucessor_xc->owner != XID::from_ptr(sucessor_clsn))
        goto try_get_sucessor;

      LSN sucessor_end = volatile_read(sucessor_xc->end);
      // overwriter might haven't committed, be serialized after me, or before me
      if (sucessor_end == INVALID_LSN) // not even in precommit, don't bother
          ;
      else if (sucessor_end > clsn)    // serialzed after me, (dependency trivially satisfied as I as the reader will (hopefully) commit first)
          ;
      else {
        if (wait_for_commit_result(sucessor_xc)) {    // either wait or give conservative estimation
          // now read the sucessor stamp (sucessor's clsn, as sucessor needs to fill its clsn to the overwritten tuple's slsn at post-commit)
          if (sucessor_end < xc->succ)
            xc->succ = sucessor_end;
        } // otherwise aborted, ignore
      }
    }
    else {    // overwriter already fully committed (slsn available)
      ASSERT(sucessor_clsn.asi_type() == fat_ptr::ASI_LOG);
      if (tuple->slsn < xc->succ)
        xc->succ = tuple->slsn;
    }
  }

  if (not ssn_check_exclusion(xc))
    signal_abort(ABORT_REASON_SSN_EXCLUSION_FAILURE);

  // ok, can really commit if we reach here
  log->commit(NULL);
  RCU::rcu_exit();

  // change state
  volatile_write(xc->state, TXN_CMMTD);

  // post-commit: stuff access stamps for reads; init new versions
  for (auto &w : write_set) {
    dbtuple *tuple = w.first;
    object *obj = (object *)w.second->get_tuple_vector()->begin_ptr(tuple->oid)->offset();
    if (obj->_next != NULL_PTR) {   // update, not insert
      dbtuple *next_tuple = (dbtuple *)((object *)obj->_next.offset())->payload();
      ASSERT(volatile_read(next_tuple->clsn).asi_type());
      volatile_write(next_tuple->slsn._val, xc->succ._val);
    }
    tuple->clsn = clsn.to_log_ptr();
    //ASSERT(readers_reg.count_readers((void *)it->first.tree_ptr, it->first.oid, LSN::from_ptr(tuple->clsn)) == 0);
    //^^^^^ the above isn't totally true: to make it is, we need to provide xid to count_readers to only include
    //those that are older than me.
    ASSERT(tuple->clsn.asi_type() == fat_ptr::ASI_LOG);
    volatile_write(tuple->xlsn._val, clsn._val);
  }

  for (auto &r : read_set) {
    dbtuple *tuple = r.first;
    ASSERT(tuple->clsn.asi_type() == fat_ptr::ASI_LOG);
    LSN xlsn = INVALID_LSN;
    do {
      xlsn = volatile_read(tuple->xlsn);
    }
    while (xlsn < clsn and not __sync_bool_compare_and_swap(&tuple->xlsn._val, xlsn._val, clsn._val));
    // remove myself from readers set, so others won't see "invalid XID" while enumerating readers
    readers_reg.deregister_tx(tuple->rlist, r.second.reader_pos);
  }

  // done
  xid_free(xid);
}
#else
template <template <typename> class Protocol, typename Traits>
void
transaction<Protocol, Traits>::si_commit()
{
  xid_context* xc = xid_get_context(xid);

  PERF_DECL(
      static std::string probe0_name(
        std::string(__PRETTY_FUNCTION__) + std::string(":total:")));
  ANON_REGION(probe0_name.c_str(), &transaction_base::g_txn_commit_probe0_cg);

  switch (state()) {
  case TXN_EMBRYO:
  case TXN_ACTIVE:
    xc->state = TXN_COMMITTING;
    break;
  case TXN_CMMTD:
  case TXN_COMMITTING: 
  case TXN_ABRTD:
    ALWAYS_ASSERT(false);
  }
  
  // avoid cross init after goto do_abort
  typename access_set_map::iterator it     = access_set.begin();
  typename access_set_map::iterator it_end = access_set.end();

  INVARIANT(log);
  // get clsn, abort if failed
  RCU::rcu_enter();
  xc->end = log->pre_commit();
  if (xc->end == INVALID_LSN)
      signal_abort(ABORT_REASON_INTERNAL);
  log->commit(NULL);
  RCU::rcu_exit();

  // change state
  volatile_write(xid_get_context(xid)->state, TXN_CMMTD);

  // post-commit cleanup: install clsn to tuples
  // (traverse write-tuple)
  // stuff clsn in tuples in write-set
  for (; it != it_end; ++it) {
    dbtuple* tuple = reinterpret_cast<dbtuple *>(it->first.tree_ptr->fetch_version(it->first.oid, xid));
    if (it->second.is_write()) {
      tuple->clsn = xc->end.to_log_ptr();
      INVARIANT(tuple->clsn.asi_type() == fat_ptr::ASI_LOG);
    }
  }

  // done
  xid_free(xid);
}
#endif

typedef object_vector<typename concurrent_btree::value_type> tuple_vector_type;
// FIXME: tzwang: note: we only try once in this function. If it
// failed (returns false) then the caller (supposedly do_tree_put)
// should fallback to normal update procedure.
template <template <typename> class Protocol, typename Traits>
bool
transaction<Protocol, Traits>::try_insert_new_tuple(
    concurrent_btree *btr,
    const std::string *key,
	object* value,
    dbtuple::tuple_writer_t writer)
{
  INVARIANT(key);
  char*p = (char*)value;
  dbtuple* tuple = reinterpret_cast<dbtuple*>(p + sizeof(object));
  tuple_vector_type* tuple_vector = btr->get_tuple_vector();
  tuple->oid = tuple_vector->alloc();
  fat_ptr new_head = fat_ptr::make( value, INVALID_SIZE_CODE, 0);
  while(!tuple_vector->put( tuple->oid, new_head));

  typename concurrent_btree::insert_info_t insert_info;
  if (unlikely(!btr->insert_if_absent(
          varkey(*key), (typename concurrent_btree::value_type) tuple, &insert_info))) {
    VERBOSE(std::cerr << "insert_if_absent failed for key: " << util::hexify(key) << std::endl);
    ++transaction_base::g_evt_dbtuple_write_insert_failed;
    return false;
  }
  VERBOSE(std::cerr << "insert_if_absent suceeded for key: " << util::hexify(key) << std::endl
                    << "  new dbtuple is " << util::hexify(tuple) << std::endl);

  // insert to log
  // FIXME: tzwang: leave pdest as null and FID is always 1 now.
  INVARIANT(log);
  auto record_size = align_up((size_t)tuple->size);
  auto size_code = encode_size_aligned(record_size);
  log->log_insert(1,
                  tuple->oid,
                  fat_ptr::make(tuple, size_code),
                  DEFAULT_ALIGNMENT_BITS, NULL);
  // update write_set
  write_set[tuple] = btr;
#ifdef TRACE_FOOTPRINT  // FIXME: get stats on how much is empty???
  FP_TRACE::print_access(xid, std::string("insert"), (uintptr_t)btr, tuple, NULL);
#endif
  return true;
}

template <template <typename> class Protocol, typename Traits>
template <typename ValueReader>
bool
transaction<Protocol, Traits>::do_tuple_read(
    concurrent_btree *btr_ptr, dbtuple *tuple, ValueReader &value_reader)
{
  INVARIANT(tuple);
  ++evt_local_search_lookups;

  // do the actual tuple read
  dbtuple::ReadStatus stat;
  {
    PERF_DECL(static std::string probe0_name(std::string(__PRETTY_FUNCTION__) + std::string(":do_read:")));
    ANON_REGION(probe0_name.c_str(), &private_::txn_btree_search_probe0_cg);
    tuple->prefetch();
    stat = tuple->stable_read(value_reader, this->string_allocator());
    if (unlikely(stat == dbtuple::READ_FAILED)) {
      const transaction_base::abort_reason r = transaction_base::ABORT_REASON_UNSTABLE_READ;
      signal_abort(r);
    }
  }
  INVARIANT(stat == dbtuple::READ_EMPTY ||
            stat == dbtuple::READ_RECORD);
  if (stat == dbtuple::READ_EMPTY) {
    ++transaction_base::g_evt_read_logical_deleted_node_search;
    return false;
  }

#ifdef TRACE_FOOTPRINT  // FIXME: get stats on how much is empty???
  FP_TRACE::print_access(xid, std::string("read"), (uintptr_t)btr_ptr, tuple, NULL);
#endif
  // SSN stamps and check
  if (tuple->clsn.asi_type() == fat_ptr::ASI_LOG and find_write_set(tuple) == write_set.end() and find_read_set(tuple) == read_set.end()) {
      xid_context* xc = xid_get_context(xid);
      ASSERT(xc);
      LSN v_clsn = LSN::from_ptr(tuple->clsn);
      // \eta - largest predecessor. So if I read this tuple, I should commit
      // after the tuple's creator (trivial, as this is committed version, so
      // this tuple's clsn can only be a predecessor of me): so just update
      // my \eta if needed.
      if (xc->pred < v_clsn)
          xc->pred = v_clsn;

      // Now if this tuple was overwritten by somebody, this means if I read
      // it, that overwriter will have anti-dependency on me (I must be
      // serialized before the overwriter), and it already committed (as a
      // successor of mine), so I need to update my \pi for the SSN check.
      // This is the easier case of anti-dependency (the other case is T1
      // already read a (then latest) version, then T2 comes to overwrite it).
      LSN tuple_slsn = volatile_read(tuple->slsn);
      if (tuple_slsn == INVALID_LSN) {   // no overwrite so far
        int pos = -1;
        ASSERT(tuple->rlist);
        //if (likely(tuple->rlist))
          pos = readers_reg.register_tx(tuple->rlist, xid);
        //else
          //pos = readers_reg.register_tx((uintptr_t)tuple, xid);
        read_set[tuple] = read_record_t(btr_ptr, pos);
      }
      else if (xc->succ > tuple_slsn)
        xc->succ = tuple_slsn; // \pi
      if (not ssn_check_exclusion(xc))
        signal_abort(ABORT_REASON_SSN_EXCLUSION_FAILURE);
  }

  return true;
}

#endif /* _NDB_TXN_IMPL_H_ */