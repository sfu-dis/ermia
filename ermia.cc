#include "dbcore/rcu.h"
#include "dbcore/sm-chkpt.h"
#include "dbcore/sm-cmd-log.h"
#include "dbcore/sm-rep.h"
#include "dbcore/sm-oid.h"
#include "dbcore/sm-dir-it.h"

#include "ermia.h"
#include "txn.h"

namespace ermia {

// Engine initialization, including creating the OID, log, and checkpoint
// managers and recovery if needed.
Engine::Engine() {
  config::sanity_check();

  if (config::is_backup_srv()) {
    rep::BackupStartReplication();
  } else {
    ALWAYS_ASSERT(config::log_dir.size());
    ALWAYS_ASSERT(not logmgr);
    ALWAYS_ASSERT(not oidmgr);
    sm_log::allocate_log_buffer();
    logmgr = sm_log::new_log(config::recover_functor, nullptr);
    sm_oid_mgr::create();
    if (config::command_log) {
      CommandLog::cmd_log = new CommandLog::CommandLogManager();
    }
    ALWAYS_ASSERT(logmgr);
    ALWAYS_ASSERT(oidmgr);

    LSN chkpt_lsn = logmgr->get_chkpt_start();
    if (config::enable_chkpt) {
      chkptmgr = new sm_chkpt_mgr(chkpt_lsn);
    }

    // The backup will want to recover in another thread
    if (sm_log::need_recovery) {
      logmgr->recover();
    }
  }
}

TableDescriptor *Engine::CreateTable(const char *name) {
  auto *td = TableDescriptor::New(name);

  if (!sm_log::need_recovery && !config::is_backup_srv()) {
    // Note: this will insert to the log and therefore affect min_flush_lsn,
    // so must be done in an sm-thread which must be created by the user
    // application (not here in ERMIA library).
    ASSERT(ermia::logmgr);

    // TODO(tzwang): perhaps make this transactional to allocate it from
    // transaction string arena to avoid malloc-ing memory (~10k size).
    char *log_space = (char *)malloc(sizeof(sm_tx_log_impl));
    ermia::sm_tx_log *log = ermia::logmgr->new_tx_log(log_space);
    td->Initialize();
    log->log_table(td->GetTupleFid(), td->GetKeyFid(), td->GetName());
    log->commit(nullptr);
    free(log_space);
  }
  return td;
}

void Engine::LogIndexCreation(bool primary, FID table_fid, FID index_fid, const std::string &index_name) {
  if (!sm_log::need_recovery && !config::is_backup_srv()) {
    // Note: this will insert to the log and therefore affect min_flush_lsn,
    // so must be done in an sm-thread which must be created by the user
    // application (not here in ERMIA library).
    ASSERT(ermia::logmgr);

    // TODO(tzwang): perhaps make this transactional to allocate it from
    // transaction string arena to avoid malloc-ing memory (~10k size).
    char *log_space = (char *)malloc(sizeof(sm_tx_log_impl));
    ermia::sm_tx_log *log = ermia::logmgr->new_tx_log(log_space);
    log->log_index(table_fid, index_fid, index_name, primary);
    log->commit(nullptr);
    free(log_space);
  }
}

void Engine::CreateIndex(const char *table_name, const std::string &index_name, bool is_primary, bool is_unique) {
  auto *td = TableDescriptor::Get(table_name);
  ALWAYS_ASSERT(td);
  auto *index = new ConcurrentMasstreeIndex(table_name, index_name, is_primary);
  if (is_primary) {
    td->SetPrimaryIndex(index, index_name);
    index->SetUnique(true);
  } else {
    td->AddSecondaryIndex(index, index_name);
    index->SetUnique(is_unique);
  }
  FID index_fid = index->GetIndexFid();
  LogIndexCreation(is_primary, td->GetTupleFid(), index_fid, index_name);
}

rc_t ConcurrentMasstreeIndex::Scan(transaction *t, const varstr &start_key,
                                   const varstr *end_key,
                                   ScanCallback &callback, str_arena *arena) {
  MARK_REFERENCED(arena);
  SearchRangeCallback c(callback);
  ASSERT(c.return_code._val == RC_FALSE);

  t->ensure_active();
  if (end_key) {
    VERBOSE(std::cerr << "txn_btree(0x" << util::hexify(intptr_t(this))
                      << ")::search_range_call [" << util::hexify(start_key)
                      << ", " << util::hexify(*end_key) << ")" << std::endl);
  } else {
    VERBOSE(std::cerr << "txn_btree(0x" << util::hexify(intptr_t(this))
                      << ")::search_range_call [" << util::hexify(start_key)
                      << ", +inf)" << std::endl);
  }

  if (!unlikely(end_key && *end_key <= start_key)) {
    XctSearchRangeCallback cb(t, &c);

    varstr uppervk;
    if (end_key) {
      uppervk = *end_key;
    }
    masstree_.search_range_call(start_key, end_key ? &uppervk : nullptr, cb,
                                t->xc);
  }
  return c.return_code;
}

rc_t ConcurrentMasstreeIndex::ReverseScan(transaction *t,
                                          const varstr &start_key,
                                          const varstr *end_key,
                                          ScanCallback &callback,
                                          str_arena *arena) {
  MARK_REFERENCED(arena);
  SearchRangeCallback c(callback);
  ASSERT(c.return_code._val == RC_FALSE);

  t->ensure_active();
  if (!unlikely(end_key && start_key <= *end_key)) {
    XctSearchRangeCallback cb(t, &c);

    varstr lowervk;
    if (end_key) {
      lowervk = *end_key;
    }
    masstree_.rsearch_range_call(start_key, end_key ? &lowervk : nullptr, cb,
                                 t->xc);
  }
  return c.return_code;
}

std::map<std::string, uint64_t> ConcurrentMasstreeIndex::Clear() {
  PurgeTreeWalker w;
  masstree_.tree_walk(w);
  masstree_.clear();
  return std::map<std::string, uint64_t>();
}

void ConcurrentMasstreeIndex::GetRecord(transaction *t, rc_t &rc, const varstr &key,
                                        varstr &value, OID *out_oid) {
  OID oid = INVALID_OID;
  rc = {RC_INVALID};
  ConcurrentMasstree::versioned_node_t sinfo;

  if (!t) {
    auto e = MM::epoch_enter();
    rc._val = masstree_.search(key, oid, e, &sinfo) ? RC_TRUE : RC_FALSE;
    MM::epoch_exit(0, e);
  } else {
    t->ensure_active();
    bool found = masstree_.search(key, oid, t->xc->begin_epoch, &sinfo);

    dbtuple *tuple = nullptr;
    if (found) {
      // Key-OID mapping exists, now try to get the actual tuple to be sure
      if (config::is_backup_srv()) {
        tuple = oidmgr->BackupGetVersion(
            table_descriptor->GetTupleArray(),
            table_descriptor->GetPersistentAddressArray(), oid, t->xc);
      } else {
        tuple =
            oidmgr->oid_get_version(table_descriptor->GetTupleArray(), oid, t->xc);
      }
      if (!tuple) {
        found = false;
      }
    }

    if (found) {
      volatile_write(rc._val, t->DoTupleRead(tuple, &value)._val);
    } else if (config::phantom_prot) {
      volatile_write(rc._val, DoNodeRead(t, sinfo.first, sinfo.second)._val);
    } else {
      volatile_write(rc._val, RC_FALSE);
    }
    ASSERT(rc._val == RC_FALSE || rc._val == RC_TRUE);
  }

  if (out_oid) {
    *out_oid = oid;
  }
}

DirIterator *ConcurrentMasstreeIndex::GetRecordMultiIt(transaction *t, rc_t &rc, const varstr &key) {
    rc = {RC_INVALID};
    OID dir_oid = INVALID_OID;
    std::vector<OID> oids;
    ermia::varstr tmpval;
    auto dir_it = new DirIterator(t, table_descriptor);
    if (!t) {
        auto e = MM::epoch_enter();
        rc._val = masstree_.search(key, dir_oid, e, nullptr) ? RC_TRUE : RC_FALSE;
        MM::epoch_exit(0, e);
    } else {
        t->ensure_active();
        bool found = masstree_.search(key, dir_oid, t->xc->begin_epoch, nullptr);
        dbtuple *tuple = nullptr;
        if (found) {
            LOG_IF(FATAL, config::is_backup_srv()) << "GetRecordMulti is not supportted for backup server";
            dir_it->dirp = oidmgr->dirp(table_descriptor->GetTupleArray(), dir_oid);
            // SKIP THE heavy oid_get_dir
            // bool ok = oidmgr->oid_get_dir(table_descriptor->GetTupleArray(), dir_oid, *(dir_it->_ptr));
            //  ALWAYS_ASSERT(ok);
            volatile_write(rc._val, RC_TRUE);
            return dir_it;
        } else {
            volatile_write(rc._val, RC_FALSE);
            delete dir_it;
            return nullptr;
        }
    }
 
}

void ConcurrentMasstreeIndex::GetRecordMulti(transaction *t, rc_t &rc, const varstr &key,
        std::vector<varstr> &result_vec, std::vector<OID> *out_oid) {
    rc = {RC_INVALID};
    OID dir_oid = INVALID_OID;
    std::vector<OID> oids;
    ermia::varstr tmpval;
    if (!t) {
        auto e = MM::epoch_enter();
        rc._val = masstree_.search(key, dir_oid, e, nullptr) ? RC_TRUE : RC_FALSE;
        MM::epoch_exit(0, e);
    } else {
        t->ensure_active();
        bool found = masstree_.search(key, dir_oid, t->xc->begin_epoch, nullptr);
        dbtuple *tuple = nullptr;
        if (found) {
            LOG_IF(FATAL, config::is_backup_srv()) << "GetRecordMulti is not supportted for backup server";
            bool ok = oidmgr->oid_get_dir(table_descriptor->GetTupleArray(), dir_oid, oids);
            ALWAYS_ASSERT(ok);
            for (auto &o : oids) {
                tuple = oidmgr->oid_get_version(table_descriptor->GetTupleArray(), o, t->xc);
                if (!tuple) {
                    DLOG(WARNING) << "(SKIPPED) Some tuple is empty: OID = " << std::hex << o;
                    found = false;
                }

                if (found) {
                  bool ret = t->DoTupleRead(tuple, &tmpval)._val;
                  if (!ret) {
                      DLOG(WARNING) << "(SKIPPED) Cannot do tuple read for OID = " << std::hex << o;
                      continue;
                  }
                  result_vec.push_back(tmpval);
                } else if (config::phantom_prot) {
                  // volatile_write(rc._val, DoNodeRead(t, sinfo.first, sinfo.second)._val);
                } else {
                    continue;
                }
            }
            volatile_write(rc._val, RC_TRUE);
            return;
        } else {
            volatile_write(rc._val, RC_FALSE);
            return;
        }
    }
}


void ConcurrentMasstreeIndex::PurgeTreeWalker::on_node_begin(
    const typename ConcurrentMasstree::node_opaque_t *n) {
  ASSERT(spec_values.empty());
  spec_values = ConcurrentMasstree::ExtractValues(n);
}

void ConcurrentMasstreeIndex::PurgeTreeWalker::on_node_success() {
  spec_values.clear();
}

void ConcurrentMasstreeIndex::PurgeTreeWalker::on_node_failure() {
  spec_values.clear();
}

bool ConcurrentMasstreeIndex::InsertIfAbsent(transaction *t, const varstr &key,
                                             OID oid) {
  typename ConcurrentMasstree::insert_info_t ins_info;
  bool inserted = masstree_.insert_if_absent(key, oid, t->xc, &ins_info);

  if (!inserted) {
    return false;
  }

  if (config::phantom_prot && !t->masstree_absent_set.empty()) {
    // Update node version number
    ASSERT(ins_info.node);
    auto it = t->masstree_absent_set.find(ins_info.node);
    if (it != t->masstree_absent_set.end()) {
      if (unlikely(it->second != ins_info.old_version)) {
        // Important: caller should unlink the version, otherwise we risk
        // leaving a dead version at chain head -> infinite loop or segfault...
        return false;
      }
      // otherwise, bump the version
      it->second = ins_info.new_version;
    }
  }
  return true;
}

////////////////// Index interfaces /////////////////

bool ConcurrentMasstreeIndex::InsertOID(transaction *t, const varstr &key, OID oid) {
  bool inserted = false;
  if (this->is_unique) {
    inserted = InsertIfAbsent(t, key, oid);
  } else {
    inserted = InsertToDir(t, key, oid);
  }
  if (inserted) {
    t->LogIndexInsert(this, oid, &key);
    if (config::enable_chkpt) {
      auto *key_array = GetTableDescriptor()->GetKeyArray();
      volatile_write(key_array->get(oid)->_ptr, 0);
    }
  }
  return inserted;
}

static inline OID *find_empty_dir_entry(transaction *t, OID *chunk, ermia::TableDescriptor *td);

inline int printhex(const varstr &key) {
  auto data = key.data();
  auto len = key.size();
  int cnt = 0;
  for (int i = 0; i < len; i++) {
    printf("%x%x %c ", ((unsigned int)data[i] & 0xF0) >> 4,
           (unsigned int)data[i] & 0x0F, data[i]);
    cnt++;
    if (cnt == 8) {
      printf(" ");
    }
    if (cnt == 16) {
      printf("\n");
      cnt = 0;
    }
  }
  if (len % 16) printf("\n");
  return 0;
}

/* OID_DIR Object structure:
 * OID_DIR is an array that stores the OID to the real data, the last entry for in the OID_DIR object
 * Stores the OID to another OID_DIR Object (sub-dir), so that the OID_DIR size can be very large (2^32 - 1)
 * The first level OID_DIR Object is special, It contains a OID_DIR_HEADER_SIZE length of header
 */
// TODO(jianqiuz): Uniqueness check for OID dir. We shouldn't have two same OID entry in one OID Dir.
bool ConcurrentMasstreeIndex::InsertToDir(transaction *t, const varstr &key, OID oid) {
  ALWAYS_ASSERT(!this->IsUnique());
  t->ensure_active();
  OID dir_oid = INVALID_OID;
retry:
  auto found = masstree_.search(key, dir_oid, t->xc->begin_epoch);
  auto td = this->GetTableDescriptor();
  ALWAYS_ASSERT(td);
  /* Empty entry, create and insert the first record */
  if (!found) {
      DLOG(INFO) << "Insert the first entry to oid-dir";
      uint32_t size = sizeof(OID) * OID_DIR_SIZE;
      OID *oid_dir = reinterpret_cast<OID *>(MM::allocate(size));
      fat_ptr dirp = NULL_PTR;
      oid_dir[OID_DIR_COUNT_INDEX] = 1;
      oid_dir[OID_DIR_LATCH_INDEX] = 0x00000000;
      oid_dir[OID_DIR_HEADER_SIZE] = oid;
      {
        dir_oid = oidmgr->alloc_oid(td->GetTupleFid());
        ALWAYS_ASSERT(dir_oid != INVALID_OID);
        // TODO(jianqiuz): Is the size code okay?
        dirp = fat_ptr::make(oid_dir, 0, fat_ptr::ASI_DIR_FLAG);
        oidmgr->oid_put_new(td->GetTupleFid(), dir_oid, dirp);
        DLOG(INFO) << "Insert the oid dir fat pointer addr: " << std::hex << dirp._ptr << ", Original addr: " << std::hex << oid_dir;
      }
      bool ok = masstree_.insert_if_absent(key, dir_oid, t->xc);
      if (ok) {
        return true;
      }
      oidmgr->free_oid(td->GetTupleFid(), dir_oid);
      // MM::deallocate(dirp);
      goto retry;
  }
  // FIXME(jianqiuz): Currently using MCS_LOCK, but
  // Maybe we can utilize the auxilary array and do a mutex?
  auto dirp = oidmgr->oid_get(td->GetTupleFid(), dir_oid);
  DLOG(INFO) << "Get the oid dir pointer addr: " << std::hex << dirp.offset();
  ALWAYS_ASSERT(dirp._ptr);
  auto oid_dir = reinterpret_cast<OID *>(dirp.offset());

  {
    XLock(oid_dir + OID_DIR_LATCH_INDEX);
    DEFER(XUnlock(oid_dir + OID_DIR_LATCH_INDEX));
    auto slot = find_empty_dir_entry(t, oid_dir, td);
    oid_dir[0] += 1;
    *slot = oid;
  }

  return true;
}


// Should only be called via InsertToDir, already entered epoch
static inline OID *find_empty_dir_entry(transaction *t, OID *chunk, ermia::TableDescriptor *td) {
    if(chunk[0] == INVALID_OID) {
        return chunk;
    }
    OID *result = nullptr;
    const uint32_t rec_count = reinterpret_cast<uint32_t>(chunk[0]);
    DLOG(INFO) << "Current record count = " << rec_count;

    auto depth = (rec_count + OID_DIR_HEADER_SIZE) / (OID_DIR_SIZE - 1);
    auto pos = (rec_count + OID_DIR_HEADER_SIZE) % (OID_DIR_SIZE - 1);

    DLOG(INFO) << "Insert the record into oid_dir depth = " << depth << " index = " << pos;
    OID new_dir_oid = INVALID_OID;
    if (!pos) {
      /* Allocate a new oid dir list */
      uint32_t size = sizeof(OID) * OID_DIR_SIZE;
      auto oid_dir = reinterpret_cast<OID *>(MM::allocate(size));

      {
        new_dir_oid = oidmgr->alloc_oid(td->GetTupleFid());
        ALWAYS_ASSERT(new_dir_oid != INVALID_OID);

        // TODO(jianqiuz): Is the size code okay? Also don't forget to add ASI FLAG for OID DIR
        fat_ptr dirp = fat_ptr::make(oid_dir, 0, fat_ptr::ASI_DIR_FLAG);
        oidmgr->oid_put_new(td->GetTupleFid(), new_dir_oid, dirp);
        DLOG(INFO) << "Insert the oid subdir fat pointer addr: " << std::hex << dirp._ptr << ", Original addr: " << std::hex << oid_dir;
      }
   }
   auto p = chunk;
   while(depth > 0) {
       if (new_dir_oid != INVALID_OID) {
           if (depth == 1) {
               p[OID_DIR_SIZE - 1] = new_dir_oid;
           }
       }
       // TODO(jianqiuz): Change the last entry to fat_ptr / ptr instead of using OID, which introduce one more indirection (cache miss)
       auto fptr = oidmgr->oid_get(td->GetTupleFid(), p[OID_DIR_SIZE - 1]);
       ALWAYS_ASSERT(fptr.asi() & fat_ptr::ASI_DIR);
       p = reinterpret_cast<OID *>(fptr.offset());
       depth -= 1;
   }
   return p + pos;
}

rc_t ConcurrentMasstreeIndex::InsertRecord(transaction *t, const varstr &key, varstr &value, OID *out_oid) {
  // For primary index only
  ALWAYS_ASSERT(IsPrimary());

  ASSERT((char *)key.data() == (char *)&key + sizeof(varstr));
  t->ensure_active();

  // Insert to the table first
  dbtuple *tuple = nullptr;
  OID oid = t->Insert(table_descriptor, &value, &tuple);

  // Done with table record, now set up index
  ASSERT((char *)key.data() == (char *)&key + sizeof(varstr));
  if (!InsertOID(t, key, oid)) {
    if (config::enable_chkpt) {
      volatile_write(table_descriptor->GetKeyArray()->get(oid)->_ptr, 0);
    }
    return rc_t{RC_ABORT_INTERNAL};
  }

  // Succeeded, now put the key there if we need it
  if (config::enable_chkpt) {
    // XXX(tzwang): only need to install this key if we need chkpt; not a
    // realistic setting here to not generate it, the purpose of skipping
    // this is solely for benchmarking CC.
    varstr *new_key =
        (varstr *)MM::allocate(sizeof(varstr) + key.size());
    new (new_key) varstr((char *)new_key + sizeof(varstr), 0);
    new_key->copy_from(&key);
    auto *key_array = table_descriptor->GetKeyArray();
    key_array->ensure_size(oid);
    oidmgr->oid_put(key_array, oid,
                    fat_ptr::make((void *)new_key, INVALID_SIZE_CODE));
  }

  if (out_oid) {
    *out_oid = oid;
  }

  return rc_t{RC_TRUE};
}

rc_t ConcurrentMasstreeIndex::UpdateRecord(transaction *t, const varstr &key, varstr &value) {
  // For primary index only
  ALWAYS_ASSERT(IsPrimary());

  // Search for OID
  OID oid = 0;
  rc_t rc = {RC_INVALID};
  GetOID(key, rc, t->xc, oid);

  if (rc._val == RC_TRUE) {
    rc_t rc = t->Update(table_descriptor, oid, &key, &value);
    return rc;
  } else {
    return rc_t{RC_ABORT_INTERNAL};
  }
}

rc_t ConcurrentMasstreeIndex::RemoveRecord(transaction *t, const varstr &key) {
  // For primary index only
  ALWAYS_ASSERT(IsPrimary());

  // Search for OID
  OID oid = 0;
  rc_t rc = {RC_INVALID};
  GetOID(key, rc, t->xc, oid);

  if (rc._val == RC_TRUE) {
		return t->Update(table_descriptor, oid, &key, nullptr);
  } else {
    return rc_t{RC_ABORT_INTERNAL};
  }
}

rc_t ConcurrentMasstreeIndex::DoNodeRead(
    transaction *t, const ConcurrentMasstree::node_opaque_t *node,
    uint64_t version) {
  ALWAYS_ASSERT(config::phantom_prot);
  ASSERT(node);
  auto it = t->masstree_absent_set.find(node);
  if (it == t->masstree_absent_set.end()) {
    t->masstree_absent_set[node] = version;
  } else if (it->second != version) {
    return rc_t{RC_ABORT_PHANTOM};
  }
  return rc_t{RC_TRUE};
}

void ConcurrentMasstreeIndex::XctSearchRangeCallback::on_resp_node(
    const typename ConcurrentMasstree::node_opaque_t *n, uint64_t version) {
  VERBOSE(std::cerr << "on_resp_node(): <node=0x" << util::hexify(intptr_t(n))
                    << ", version=" << version << ">" << std::endl);
  VERBOSE(std::cerr << "  " << ConcurrentMasstree::NodeStringify(n)
                    << std::endl);
  if (config::phantom_prot) {
#ifdef SSN
    if (t->flags & transaction::TXN_FLAG_READ_ONLY) {
      return;
    }
#endif
    rc_t rc = DoNodeRead(t, n, version);
    if (rc.IsAbort()) {
      caller_callback->return_code = rc;
    }
  }
}

bool ConcurrentMasstreeIndex::XctSearchRangeCallback::invoke(
    const ConcurrentMasstree *btr_ptr,
    const typename ConcurrentMasstree::string_type &k, dbtuple *v,
    const typename ConcurrentMasstree::node_opaque_t *n, uint64_t version) {
  MARK_REFERENCED(btr_ptr);
  MARK_REFERENCED(n);
  MARK_REFERENCED(version);
  t->ensure_active();
  VERBOSE(std::cerr << "search range k: " << util::hexify(k) << " from <node=0x"
                    << util::hexify(n) << ", version=" << version << ">"
                    << std::endl
                    << "  " << *((dbtuple *)v) << std::endl);
  varstr vv;
  caller_callback->return_code = t->DoTupleRead(v, &vv);
  if (caller_callback->return_code._val == RC_TRUE) {
    return caller_callback->Invoke(k, vv);
  } else if (caller_callback->return_code.IsAbort()) {
    // don't continue the read if the tx should abort
    // ^^^^^ note: see masstree_scan.hh, whose scan() calls
    // visit_value(), which calls this function to determine
    // if it should stop reading.
    return false; // don't continue the read if the tx should abort
  }
  return true;
}

////////////////// End of index interfaces //////////

////////////////// Table interfaces /////////////////
rc_t Table::Insert(transaction &t, varstr *value, OID *out_oid) {
  t.ensure_active();
  OID oid = t.Insert(td, value);
  if (out_oid) {
    *out_oid = oid;
  }
  return oid == INVALID_OID ? rc_t{RC_FALSE} : rc_t{RC_FALSE};
}

rc_t Table::Read(transaction &t, OID oid, varstr *out_value) {
  auto *tuple = oidmgr->oid_get_version(td->GetTupleArray(), oid, t.GetXIDContext());
  rc_t rc = {RC_INVALID};
  if (tuple) {
    // Record exists
    volatile_write(rc._val, t.DoTupleRead(tuple, out_value)._val);
  } else {
    volatile_write(rc._val, RC_FALSE);
  }
  ASSERT(rc._val == RC_FALSE || rc._val == RC_TRUE);
  return rc;
}

rc_t Table::Update(transaction &t, OID oid, varstr &value) {
  return t.Update(td, oid, &value);
}

rc_t Table::Remove(transaction &t, OID oid) {
  return t.Update(td, oid, nullptr);
}

////////////////// End of Table interfaces //////////

OrderedIndex::OrderedIndex(std::string table_name, bool is_primary) : is_primary(is_primary) {
  table_descriptor = TableDescriptor::Get(table_name);
  self_fid = oidmgr->create_file(true);
}

} // namespace ermia
