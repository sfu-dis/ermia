/* 
 * OID Dir Iterator, used for Index query
 */
#pragma once
#include "sm-config.h"
#include "../txn.h"
namespace ermia {

struct DirIterator {
  OID *dirp;
  TableDescriptor *td;
  transaction *t;
  int idx = 0;
  DirIterator(transaction *t, TableDescriptor *td) : td(td), t(t) {}
  DirIterator() {}
  ~DirIterator() {}

  const ermia::varstr next(bool &eof) {
redo:
    ermia::varstr tmpval; 
    auto o = oidmgr->dir_get_index(td->GetTupleArray(), dirp, idx + 1, eof);
    if (eof) {
        return tmpval;
    }
    dbtuple *tuple = nullptr;
    tuple = oidmgr->oid_get_version(td->GetTupleArray(), o, t->xc);
    if (!tuple) {
        DLOG(WARNING) << "(SKIPPED) Some tuple is empty: OID = " << std::hex << o;
    }
    if (tuple) {
        auto ret = t->DoTupleRead(tuple, &tmpval)._val;
        ALWAYS_ASSERT(ret == RC_TRUE);
	    idx += 1;
        return tmpval;
    } else {
        idx += 1;
        goto redo;
    }
  }

  void reset() {
    t = nullptr;
    td = nullptr;
    idx = 0;
  }
};

}
