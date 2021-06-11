/* 
 * OID Dir Iterator, used for Index query
 */
#pragma once
#include "sm-config.h"
#include "../txn.h"
namespace ermia {

struct DirIterator {
  /* For debug use, store the oid_dir ptr */
  OID *dirp;
  TableDescriptor *td;
  transaction *t;
  int idx = 0;
  DirIterator(transaction *t, TableDescriptor *td) : td(td), t(t) {

  };

  ~DirIterator() {
      
  }

  const ermia::varstr next(bool &eof) {
redo:
    ermia::varstr tmpval; 
    auto o = oidmgr->dir_get_index(td->GetTupleArray(), dirp, idx + 1, eof);
    if (eof) {
        return tmpval;
    }
    dbtuple *tuple = nullptr;
    tuple = oidmgr->oid_get_version(td->GetTupleArray(), o, t->xc);
    bool found = true;
    if (!tuple) {
        DLOG(WARNING) << "(SKIPPED) Some tuple is empty: OID = " << std::hex << o;
        found = false;
    }
    if (found) {
        bool ret = t->DoTupleRead(tuple, &tmpval)._val;
        if (!ret) {
            DLOG(WARNING) << "(SKIPPED) Cannot do tuple read for OID = " << std::hex << o;
            idx += 1;
            goto redo;
        }
	    idx += 1;
        return tmpval;
    } else if (config::phantom_prot) {
        // volatile_write(rc._val, DoNodeRead(t, sinfo.first, sinfo.second)._val);
        eof = true;
        return tmpval;
    } else {
        idx += 1;
        goto redo;
    }

  }


  // When cleanup, delete it
};

}
