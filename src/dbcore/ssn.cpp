#include "ssn.h"
#ifdef USE_PARALLEL_SSN
namespace TXN {

uint64_t ssn_abort_count = 0;
uint64_t __thread tls_ssn_abort_count;
readers_list rlist;

bool __attribute__((noinline))
wait_for_commit_result(xid_context *xc) {
    while (volatile_read(xc->state) == TXN_COMMITTING) { /* spin */ }
    return volatile_read(xc->state) == TXN_CMMTD;
}

typedef dbtuple::rl_bitmap_t rl_bitmap_t;
static __thread rl_bitmap_t tls_bitmap_entry = 0;
static rl_bitmap_t claimed_bitmap_entries = 0;

void assign_reader_bitmap_entry() {
    if (tls_bitmap_entry)
        return;

    rl_bitmap_t old_bitmap = volatile_read(claimed_bitmap_entries);
 retry:
    rl_bitmap_t new_bitmap = old_bitmap | (old_bitmap+1);
    rl_bitmap_t cur_bitmap = __sync_val_compare_and_swap(&claimed_bitmap_entries, old_bitmap, new_bitmap);
    if (old_bitmap != cur_bitmap) {
        old_bitmap = cur_bitmap;
        goto retry;
    }

    tls_bitmap_entry = new_bitmap ^ old_bitmap;
    rl_bitmap_t forbidden_bits = -(rl_bitmap_t(1) << readers_list::XIDS_PER_READER_KEY);
    ALWAYS_ASSERT(not (tls_bitmap_entry & forbidden_bits));
}

void deassign_reader_bitmap_entry() {
    ALWAYS_ASSERT(tls_bitmap_entry);
    ALWAYS_ASSERT(claimed_bitmap_entries & tls_bitmap_entry);
    __sync_fetch_and_xor(&claimed_bitmap_entries, tls_bitmap_entry);
    tls_bitmap_entry = 0;
    summarize_ssn_aborts();
}

void summarize_ssn_aborts()
{
    __sync_fetch_and_add(&ssn_abort_count, tls_ssn_abort_count);
    if (not claimed_bitmap_entries)
        printf("--- SSN aborts: %lu\n", ssn_abort_count);
}

bool
ssn_register_reader_tx(dbtuple *t, XID xid)
{
    rl_bitmap_t old_bitmap = volatile_read(t->rl_bitmap);
    if (old_bitmap & tls_bitmap_entry)
        return false;
    
    int xid_pos = __builtin_ctz(tls_bitmap_entry);
    ASSERT(xid_pos >= 0 and xid_pos < readers_list::XIDS_PER_READER_KEY);
    __sync_fetch_and_or(&t->rl_bitmap, tls_bitmap_entry);
    return true;
}

void
ssn_deregister_reader_tx(dbtuple *t)
{
    ASSERT(tls_bitmap_entry);
    __sync_fetch_and_xor(&t->rl_bitmap, tls_bitmap_entry);
}

// register tx in the global rlist (called at tx start)
void
ssn_register_tx(XID xid)
{
    volatile_write(rlist.xids[__builtin_ctz(tls_bitmap_entry)]._val, xid._val);
}

// deregister tx in the global rlist (called at tx end)
void
ssn_deregister_tx(XID xid)
{
    volatile_write(rlist.xids[__builtin_ctz(tls_bitmap_entry)]._val, 0);
}

};  // end of namespace
#endif
