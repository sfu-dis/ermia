// Copyright (c) Microsoft Corporation. All rights reserved.
// Adapted by Xiangpeng Hao
// Licensed under the MIT license.

#pragma once

#include <atomic>
#include <cstdint>
#include <list>
#include <mutex>
#include <thread>
#include "tls_thread.h"
#include "utils.h"

/// A "timestamp" that is used to determine when it is safe to reuse memory in
/// data structures that are protected with an EpochManager. Epochs are
/// opaque to threads and data structures that use the EpochManager. They
/// may receive Epochs from some of the methods, but they never need to
/// perform any computation on them, other than to pass them back to the
/// EpochManager on future calls (for example, EpochManager::GetCurrentEpoch()
/// and EpochManager::IsSafeToReclaim()).
typedef uint64_t Epoch;

/// Used to ensure that concurrent accesses to data structures don't reuse
/// memory that some threads may be accessing. Specifically, for many lock-free
/// data structures items are "unlinked" when they are removed. Unlinked items
/// cannot be disposed until it is guaranteed that no threads are accessing or
/// will ever access the memory associated with the item again. EpochManager
/// makes it easy for data structures to determine if it is safe to reuse
/// memory by "timestamping" removed items and the entry/exit of threads
/// into the protected code region.
///
/// Practically, a developer "protects" some region of code by marking it
/// with calls to Protect() and Unprotect(). The developer must guarantee that
/// no pointers to internal data structure items are retained beyond the
/// Unprotect() call. Up until Unprotect(), pointers to internal items in
/// a data structure may remain safe for access (see the specific data
/// structures that use this class via IsSafeToReclaim() for documentation on
/// what items are safe to hold pointers to within the protected region).
///
/// Data structure developers must "swap" elements out of their structures
/// atomically and with a sequentially consistent store operation. This ensures
/// that all threads call Protect() in the future will not see the deleted item.
/// Afterward, the removed item must be associated with the current Epoch
/// (acquired via GetCurrentEpoch()). Data structures can use any means to
/// track the association between the removed item and the Epoch it was
/// removed during. Such removed elements must be retained and remain safe for
/// access until IsSafeToReclaim() returns true (which indicates no threads are
/// accessing or ever will access the item again).
class EpochManager
{
public:
  EpochManager();
  ~EpochManager();

  bool Initialize();
  bool Uninitialize();

  /// Enter the thread into the protected code region, which guarantees
  /// pointer stability for records in client data structures. After this
  /// call, accesses to protected data structure items are guaranteed to be
  /// safe, even if the item is concurrently removed from the structure.
  ///
  /// Behavior is undefined if Protect() is called from an already
  /// protected thread. Upon creation, threads are unprotected.
  /// \return S_OK indicates thread may now enter the protected region. Any
  ///      other return indicates a fatal problem accessing the thread local
  ///      storage; the thread may not enter the protected region. Most likely
  ///      the library has entered some non-serviceable state.
  bool Protect()
  {
    return epoch_table_->Protect(
        current_epoch_.load(std::memory_order_relaxed));
  }

  /// Exit the thread from the protected code region. The thread must
  /// promise not to access pointers to elements in the protected data
  /// structures beyond this call.
  ///
  /// Behavior is undefined if Unprotect() is called from an already
  /// unprotected thread.
  /// \return S_OK indicates thread successfully exited protected region. Any
  ///      other return indicates a fatal problem accessing the thread local
  ///      storage; the thread may not have successfully exited the protected
  ///      region. Most likely the library has entered some non-serviceable
  ///      state.
  bool Unprotect()
  {
    return epoch_table_->Unprotect(
        current_epoch_.load(std::memory_order_relaxed));
  }

  /// Get a snapshot of the current global Epoch. This is used by
  /// data structures to fetch an Epoch that is recorded along with
  /// a removed element.
  Epoch GetCurrentEpoch()
  {
    return current_epoch_.load(std::memory_order_seq_cst);
  }

  /// Returns true if an item tagged with \a epoch (which was returned by
  /// an earlier call to GetCurrentEpoch()) is safe to reclaim and reuse.
  /// If false is returned the caller then others threads may still be
  /// concurrently accessed the object inquired about.
  bool IsSafeToReclaim(Epoch epoch)
  {
    return epoch <= safe_to_reclaim_epoch_.load(std::memory_order_relaxed);
  }

  /// Returns true if the calling thread is already in the protected code
  /// region (i.e., have already called Protected()).
  bool IsProtected() { return epoch_table_->IsProtected(); }

  void BumpCurrentEpoch();

public:
  void ComputeNewSafeToReclaimEpoch(Epoch currentEpoch);

  /// Keeps track of which threads are executing in region protected by
  /// its parent EpochManager. This table does most of the work of the
  /// EpochManager. It allocates a slot in thread local storage. When
  /// threads enter the protected region for the first time it assigns
  /// the thread a slot in the table and stores its address in thread
  /// local storage. On Protect() and Unprotect() by a thread it updates
  /// the table entry that tracks whether the thread is currently operating
  /// in the protected region, and, if so, a conservative estimate of how
  /// early it might have entered.
  class MinEpochTable
  {
  public:
    /// Entries should be exactly cacheline sized to prevent contention
    /// between threads.
    enum
    {
      CACHELINE_SIZE = 64
    };

    /// Default number of entries managed by the MinEpochTable
    static const uint64_t kDefaultSize = 128;

    MinEpochTable();
    bool Initialize(uint64_t size = MinEpochTable::kDefaultSize);
    bool Uninitialize();
    bool Protect(Epoch currentEpoch);
    bool Unprotect(Epoch currentEpoch);

    Epoch ComputeNewSafeToReclaimEpoch(Epoch currentEpoch);

    /// An entry tracks the protected/unprotected state of a single
    /// thread. Threads (conservatively) the Epoch when they entered
    /// the protected region, and more loosely when they left.
    /// Threads compete for entries and atomically lock them using a
    /// compare-and-swap on the #m_threadId member.
    struct Entry
    {
      /// Construct an Entry in an unlocked and ready to use state.
      Entry() : protected_epoch{0}, last_unprotected_epoch{0}, thread_id{0} {}

      /// Threads record a snapshot of the global epoch during Protect().
      /// Threads reset this to 0 during Unprotect().
      /// It is safe that this value may actually lag the real current
      /// epoch by the time it is actually stored. This value is set
      /// with a sequentially-consistent store, which guarantees that
      /// it precedes any pointers that were removed (with sequential
      /// consistency) from data structures before the thread entered
      /// the epoch. This is critical to ensuring that a thread entering
      /// a protected region can never see a pointer to a data item that
      /// was already "unlinked" from a protected data structure. If an
      /// item is "unlinked" while this field is non-zero, then the thread
      /// associated with this entry may be able to access the unlinked
      /// memory still. This is safe, because the value stored here must
      /// be less than the epoch value associated with the deleted item
      /// (by sequential consistency, the snapshot of the epoch taken
      /// during the removal operation must have happened before the
      /// snapshot taken just before this field was updated during
      /// Protect()), which will prevent its reuse until this (and all
      /// other threads that could access the item) have called
      /// Unprotect().
      std::atomic<Epoch> protected_epoch; // 8 bytes

      /// Stores the approximate epoch under which the thread last
      /// completed an Unprotect(). This need not be very accurate; it
      /// is used to determine if a thread's slot can be preempted.
      Epoch last_unprotected_epoch; //  8 bytes

      /// ID of the thread associated with this entry. Entries are
      /// locked by threads using atomic compare-and-swap. See
      /// reserveEntry() for details.
      /// XXX(tzwang): on Linux pthread_t is 64-bit
      std::atomic<uint64_t> thread_id; //  8 bytes

      /// Ensure that each Entry is CACHELINE_SIZE.
      char ___padding[40];

      // -- Allocation policy to ensure alignment --

      /// Provides cacheline aligned allocation for the table.
      /// Note: We'll want to be even smarter for NUMA. We'll want to
      /// allocate slots that reside in socket-local DRAM to threads.
      void *operator new[](uint64_t count)
      {
#ifdef WIN32
        return _aligned_malloc(count, CACHELINE_SIZE);
#else
        void *mem = nullptr;
        int n = posix_memalign(&mem, CACHELINE_SIZE, count);
        return mem;
#endif
      }

      void operator delete[](void *p)
      {
#ifdef WIN32
        /// _aligned_malloc-specific delete.
        return _aligned_free(p);
#else
        free(p);
#endif
      }

      /// Don't allow single-entry allocations. We don't ever do them.
      /// No definition is provided so that programs that do single
      /// allocations will fail to link.
      void *operator new(uint64_t count);

      /// Don't allow single-entry deallocations. We don't ever do them.
      /// No definition is provided so that programs that do single
      /// deallocations will fail to link.
      void operator delete(void *p);
    };
    static_assert(sizeof(Entry) == CACHELINE_SIZE,
                  "Unexpected table entry size");

  public:
    bool GetEntryForThread(Entry **entry);
    Entry *ReserveEntry(uint64_t startIndex, uint64_t threadId);
    Entry *ReserveEntryForThread();
    void ReleaseEntryForThread();
    void ReclaimOldEntries();
    bool IsProtected();

  private:
#ifdef TEST_BUILD
    FRIEND_TEST(EpochManagerTest, Protect);
    FRIEND_TEST(EpochManagerTest, Unprotect);
    FRIEND_TEST(EpochManagerTest, ComputeNewSafeToReclaimEpoch);
    FRIEND_TEST(MinEpochTableTest, Initialize);
    FRIEND_TEST(MinEpochTableTest, Uninitialize);
    FRIEND_TEST(MinEpochTableTest, Protect);
    FRIEND_TEST(MinEpochTableTest, Unprotect);
    FRIEND_TEST(MinEpochTableTest, ComputeNewSafeToReclaimEpoch);
    FRIEND_TEST(MinEpochTableTest, getEntryForThread);
    FRIEND_TEST(MinEpochTableTest, getEntryForThread_OneSlotFree);
    FRIEND_TEST(MinEpochTableTest, reserveEntryForThread);
    FRIEND_TEST(MinEpochTableTest, reserveEntry);
#endif

    /// Thread protection status entries. Threads lock entries the first time
    /// the call Protect() (see reserveEntryForThread()). See documentation for
    /// the fields to specifics of how threads use their Entries to guarantee
    /// memory-stability.
    Entry *table_;

    /// The number of entries #m_table. Currently, this is fixed after
    /// Initialize() and never changes or grows. If #m_table runs out
    /// of entries, then the current implementation will deadlock threads.
    uint64_t size_;
  };

  /// A notion of time for objects that are removed from data structures.
  /// Objects in data structures are timestamped with this Epoch just after
  /// they have been (sequentially consistently) "unlinked" from a structure.
  /// Threads also use this Epoch to mark their entry into a protected region
  /// (also in sequentially consistent way). While a thread operates in this
  /// region "unlinked" items that they may be accessing will not be reclaimed.
  std::atomic<Epoch> current_epoch_;

  /// Caches the most recent result of ComputeNewSafeToReclaimEpoch() so
  /// that fast decisions about whether an object can be reused or not
  /// (in IsSafeToReclaim()). Effectively, this is periodically computed
  /// by taking the minimum of the protected Epochs in #m_epochTable and
  /// #current_epoch_.
  std::atomic<Epoch> safe_to_reclaim_epoch_;

  /// Keeps track of which threads are executing in region protected by
  /// its parent EpochManager. On Protect() and Unprotect() by a thread it
  /// updates the table entry that tracks whether the thread is currently
  /// operating in the protected region, and, if so, a conservative estimate
  /// of how early it might have entered. See MinEpochTable for more details.
  MinEpochTable *epoch_table_;

  EpochManager(const EpochManager &) = delete;
  EpochManager(EpochManager &&) = delete;
  EpochManager &operator=(EpochManager &&) = delete;
  EpochManager &operator=(const EpochManager &) = delete;
};

/// Enters an epoch on construction and exits it on destruction. Makes it
/// easy to ensure epoch protection boundaries tightly adhere to stack life
/// time even with complex control flow.
class EpochGuard
{
public:
  explicit EpochGuard(EpochManager *epoch_manager)
      : epoch_manager_{epoch_manager}, unprotect_at_exit_(true)
  {
    epoch_manager_->Protect();
  }

  /// Offer the option of having protext called on \a epoch_manager.
  /// When protect = false this implies "attach" semantics and the caller should
  /// have already called Protect. Behavior is undefined otherwise.
  explicit EpochGuard(EpochManager *epoch_manager, bool protect)
      : epoch_manager_{epoch_manager}, unprotect_at_exit_(protect)
  {
    if (protect)
    {
      epoch_manager_->Protect();
    }
  }

  ~EpochGuard()
  {
    if (unprotect_at_exit_ && epoch_manager_)
    {
      epoch_manager_->Unprotect();
    }
  }

  /// Release the current epoch manger. It is up to the caller to manually
  /// Unprotect the epoch returned. Unprotect will not be called upon EpochGuard
  /// desruction.
  EpochManager *Release()
  {
    EpochManager *ret = epoch_manager_;
    epoch_manager_ = nullptr;
    return ret;
  }

private:
  /// The epoch manager responsible for protect/unprotect.
  EpochManager *epoch_manager_;

  /// Whether the guard should call unprotect when going out of scope.
  bool unprotect_at_exit_;
};

EpochManager::EpochManager()
    : current_epoch_{1}, safe_to_reclaim_epoch_{0}, epoch_table_{nullptr} {}

EpochManager::~EpochManager() { Uninitialize(); }

/**
 * Initialize an uninitialized EpochManager. This method must be used before
 * it is safe to use an instance via any other members. Calling this on an
 * initialized instance has no effect.
 *
 * \retval S_OK Initialization was successful and instance is ready for use.
 * \retval S_FALSE This instance was already initialized; no action was taken.
 * \retval E_OUTOFMEMORY Initialization failed due to lack of heap space, the
 *      instance was left safely in an uninitialized state.
 */
bool EpochManager::Initialize()
{
  if (epoch_table_)
    return true;

  MinEpochTable *new_table = new MinEpochTable();

  if (new_table == nullptr)
    return false;

  auto rv = new_table->Initialize();
  if (!rv)
    return rv;

  current_epoch_ = 1;
  safe_to_reclaim_epoch_ = 0;
  epoch_table_ = new_table;

  return true;
}

/**
 * Uninitialize an initialized EpochManager. This method must be used before
 * it is safe to destroy or re-initialize an EpochManager. The caller is
 * responsible for ensuring no threads are protected (have started a Protect()
 * without having completed an Unprotect() and that no threads will call
 * Protect()/Unprotect() while the manager is uninitialized; failing to do
 * so results in undefined behavior. Calling Uninitialize() on an uninitialized
 * instance has no effect.
 *
 * \return Success or or may return other error codes indicating a
 *       failure deallocating the thread local storage used by the EpochManager
 *       internally. Even for returns other than success the object is safely
 *       left in an uninitialized state, though some thread local resources may
 *       not have been reclaimed properly.
 * \retval S_OK Success.
 * \retval S_FALSE Success; instance was already uninitialized, so no effect.
 */
bool EpochManager::Uninitialize()
{
  if (!epoch_table_)
    return true;

  auto s = epoch_table_->Uninitialize();

  // Keep going anyway. Even if the inner table fails to completely
  // clean up we want to clean up as much as possible.
  delete epoch_table_;
  epoch_table_ = nullptr;
  current_epoch_ = 1;
  safe_to_reclaim_epoch_ = 0;

  return s;
}

/**
 * Increment the current epoch; this should be called "occasionally" to
 * ensure that items removed from client data structures can eventually be
 * removed. Roughly, items removed from data structures cannot be reclaimed
 * until the epoch in which they were removed ends and all threads that may
 * have operated in the protected region during that Epoch have exited the
 * protected region. As a result, the current epoch should be bumped whenever
 * enough items have been removed from data structures that they represent
 * a significant amount of memory. Bumping the epoch unnecessarily may impact
 * performance, since it is an atomic operation and invalidates a read-hot
 * object in the cache of all of the cores.
 *
 * Only called by GarbageList.
 */
void EpochManager::BumpCurrentEpoch()
{
  Epoch newEpoch = current_epoch_.fetch_add(1, std::memory_order_seq_cst);
  ComputeNewSafeToReclaimEpoch(newEpoch);
}

// - private -

/**
 * Looks at all of the threads in the protected region and the current
 * Epoch and updates the Epoch that is guaranteed to be safe for
 * reclamation (stored in #m_safeToReclaimEpoch). This must be called
 * occasionally to ensure the system makes garbage collection progress.
 * For now, it's called every time bumpCurrentEpoch() is called, which
 * might work as a reasonable heuristic for when this should be called.
 */
void EpochManager::ComputeNewSafeToReclaimEpoch(Epoch currentEpoch)
{
  safe_to_reclaim_epoch_.store(
      epoch_table_->ComputeNewSafeToReclaimEpoch(currentEpoch),
      std::memory_order_release);
}

// --- EpochManager::MinEpochTable ---

/// Create an uninitialized table.
EpochManager::MinEpochTable::MinEpochTable() : table_{nullptr}, size_{} {}

/**
 * Initialize an uninitialized table. This method must be used before
 * it is safe to use an instance via any other members. Calling this on an
 * initialized instance has no effect.
 *
 * \param size The initial number of distinct threads to support calling
 *       Protect()/Unprotect(). This must be a power of two. If the table runs
 *       out of space to track threads, then calls may stall. Internally, the
 *       table may allocate additional tables to solve this, or it may reclaim
 *       entries in the table after a long idle periods of by some threads.
 *       If this number is too large it may slow down threads performing
 *       space reclamation, since this table must be scanned occasionally to
 *       make progress.
 * TODO(stutsman) Table growing and entry reclamation are not yet implemented.
 * Currently, the manager supports precisely size distinct threads over the
 * lifetime of the manager until it begins permanently spinning in all calls to
 * Protect().
 *
 * \retval S_OK Initialization was successful and instance is ready for use.
 * \retval S_FALSE Instance was already initialized; instance is ready for use.
 * \retval E_INVALIDARG \a size was not a power of two.
 * \retval E_OUTOFMEMORY Initialization failed due to lack of heap space, the
 *       instance was left safely in an uninitialized state.
 * \retval HRESULT_FROM_WIN32(TLS_OUT_OF_INDEXES) Initialization failed because
 *       TlsAlloc() failed; the table was safely left in an uninitialized state.
 */
bool EpochManager::MinEpochTable::Initialize(uint64_t size)
{
  if (table_)
    return true;

  if (!IS_POWER_OF_TWO(size))
    return false;

  Entry *new_table = new Entry[size];
  if (!new_table)
    return false;

#ifdef TEST_BUILD
  // Ensure the table is cacheline size aligned.
  RAW_CHECK(!(reinterpret_cast<uintptr_t>(new_table) & (CACHELINE_SIZE - 1)),
            "table is not cacheline aligned");
#endif

  table_ = new_table;
  size_ = size;

  return true;
}

/**
 * Uninitialize an initialized table. This method must be used before
 * it is safe to destroy or re-initialize an table. The caller is
 * responsible for ensuring no threads are protected (have started a Protect()
 * without having completed an Unprotect() and that no threads will call
 * Protect()/Unprotect() while the manager is uninitialized; failing to do
 * so results in undefined behavior. Calling Uninitialize() on an uninitialized
 * instance has no effect.
 *
 * \return May return other error codes indicating a failure deallocating the
 *      thread local storage used by the table internally. Even for returns
 *      other than success the object is safely left in an uninitialized state,
 *      though some thread local resources may not have been reclaimed
 *      properly.
 * \retval S_OK Success; resources were reclaimed and table is uninitialized.
 * \retval S_FALSE Success; no effect, since table was already uninitialized.
 */
bool EpochManager::MinEpochTable::Uninitialize()
{
  if (!table_)
    return true;

  size_ = 0;
  delete[] table_;
  table_ = nullptr;

  return true;
}

/**
 * Enter the thread into the protected code region, which guarantees
 * pointer stability for records in client data structures. After this
 * call, accesses to protected data structure items are guaranteed to be
 * safe, even if the item is concurrently removed from the structure.
 *
 * Behavior is undefined if Protect() is called from an already
 * protected thread. Upon creation, threads are unprotected.
 *
 * \param currentEpoch A sequentially consistent snapshot of the current
 *      global epoch. It is okay that this may be stale by the time it
 *      actually gets entered into the table.
 * \return S_OK indicates thread may now enter the protected region. Any
 *      other return indicates a fatal problem accessing the thread local
 *      storage; the thread may not enter the protected region. Most likely
 *      the library has entered some non-serviceable state.
 */
bool EpochManager::MinEpochTable::Protect(Epoch current_epoch)
{
  Entry *entry = nullptr;
  if (!GetEntryForThread(&entry))
  {
    return false;
  }

  entry->last_unprotected_epoch = 0;
#if 1
  entry->protected_epoch.store(current_epoch, std::memory_order_release);
  // TODO: For this to really make sense according to the spec we
  // need a (relaxed) load on entry->protected_epoch. What we want to
  // ensure is that loads "above" this point in this code don't leak down
  // and access data structures before it is safe.
  // Consistent with http://preshing.com/20130922/acquire-and-release-fences/
  // but less clear whether it is consistent with stdc++.
  std::atomic_thread_fence(std::memory_order_acquire);
#else
  entry->m_protectedEpoch.exchange(currentEpoch, std::memory_order_acq_rel);
#endif
  return true;
}

/**
 * Exit the thread from the protected code region. The thread must
 * promise not to access pointers to elements in the protected data
 * structures beyond this call.
 *
 * Behavior is undefined if Unprotect() is called from an already
 * unprotected thread.
 *
 * \param currentEpoch A any rough snapshot of the current global epoch, so
 *      long as it is greater than or equal to the value used on the thread's
 *      corresponding call to Protect().
 * \return S_OK indicates thread successfully exited protected region. Any
 *      other return indicates a fatal problem accessing the thread local
 *      storage; the thread may not have successfully exited the protected
 *      region. Most likely the library has entered some non-serviceable
 *      state.
 */
bool EpochManager::MinEpochTable::Unprotect(Epoch currentEpoch)
{
  Entry *entry = nullptr;
  if (!GetEntryForThread(&entry))
  {
    return false;
  }

#ifdef TEST_BUILD
  LOG_IF(INFO, entry->thread_id.load() != pthread_self())
      << "thread_id: " << entry->thread_id.load()
      << "; pthread_self():" << pthread_self() << std::endl;
#endif

  entry->last_unprotected_epoch = currentEpoch;
  std::atomic_thread_fence(std::memory_order_release);
  entry->protected_epoch.store(0, std::memory_order_relaxed);
  return true;
}

/**
 * Looks at all of the threads in the protected region and \a currentEpoch
 * and returns the latest Epoch that is guaranteed to be safe for reclamation.
 * That is, all items removed and tagged with a lower Epoch than returned by
 * this call may be safely reused.
 *
 * \param currentEpoch A snapshot of the current global Epoch; it is okay
 *      that the snapshot may lag the true current epoch slightly.
 * \return An Epoch that can be compared to Epochs associated with items
 *      removed from data structures. If an Epoch associated with a removed
 *      item is less or equal to the returned value, then it is guaranteed
 *      that no future thread will access the item, and it can be reused
 *      (by calling, free() on it, for example). The returned value will
 *      never be equal to or greater than the global epoch at any point, ever.
 *      That ensures that removed items in one Epoch can never be freed
 *      within the same Epoch.
 */
Epoch EpochManager::MinEpochTable::ComputeNewSafeToReclaimEpoch(
    Epoch current_epoch)
{
  Epoch oldest_call = current_epoch;
  for (uint64_t i = 0; i < size_; ++i)
  {
    Entry &entry = table_[i];
    // If any other thread has flushed a protected epoch to the cache
    // hierarchy we're guaranteed to see it even with relaxed access.
    Epoch entryEpoch = entry.protected_epoch.load(std::memory_order_acquire);
    if (entryEpoch != 0 && entryEpoch < oldest_call)
    {
      oldest_call = entryEpoch;
    }
  }
  // The latest safe epoch is the one just before the earlier unsafe one.
  return oldest_call - 1;
}

// - private -

/**
 * Get a pointer to the thread-specific state needed for a thread to
 * Protect()/Unprotect(). If no thread-specific Entry has been allocated
 * yet, then one it transparently allocated and its address is stashed
 * in the thread's local storage.
 *
 * \param[out] entry Points to an address that is populated with
 *      a pointer to the thread's Entry upon return. It is illegal to
 *      pass nullptr.
 * \return S_OK if the thread's entry was discovered or allocated; in such
 *      a successful call \a entry points to a pointer to the Entry.
 *      Any other return value means there was a problem accessing or
 *      setting values in the thread's local storage. The value pointed
 *      to by entry remains unchanged, but the library may have entered
 *      a non-serviceable state.
 */
bool EpochManager::MinEpochTable::GetEntryForThread(Entry **entry)
{
  thread_local Entry *tls = nullptr;
  if (tls)
  {
    *entry = tls;
    return true;
  }

  // No entry index was found in TLS, so we need to reserve a new entry
  // and record its index in TLS
  Entry *reserved = ReserveEntryForThread();
  tls = *entry = reserved;

  Thread::RegisterTls((uint64_t *)&tls, (uint64_t) nullptr);

  return true;
}

uint32_t Murmur3(uint32_t h)
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

/**
 * Allocate a new Entry to track a thread's protected/unprotected status and
 * return a pointer to it. This should only be called once for a thread.
 */
EpochManager::MinEpochTable::Entry *
EpochManager::MinEpochTable::ReserveEntryForThread()
{
  uint64_t current_thread_id = pthread_self();
  uint64_t startIndex = Murmur3_64(current_thread_id);
  return ReserveEntry(startIndex, current_thread_id);
}

/**
 * Does the heavy lifting of reserveEntryForThread() and is really just
 * split out for easy unit testing. This method relies on the fact that no
 * thread will ever have ID on Windows 0.
 * http://msdn.microsoft.com/en-us/library/windows/desktop/ms686746(v=vs.85).aspx
 */
EpochManager::MinEpochTable::Entry *EpochManager::MinEpochTable::ReserveEntry(
    uint64_t start_index, uint64_t thread_id)
{
  for (;;)
  {
    // Reserve an entry in the table.
    for (uint64_t i = 0; i < size_; ++i)
    {
      uint64_t indexToTest = (start_index + i) & (size_ - 1);
      Entry &entry = table_[indexToTest];
      if (entry.thread_id == 0)
      {
        uint64_t expected = 0;
        // Atomically grab a slot. No memory barriers needed.
        // Once the threadId is in place the slot is locked.
        bool success = entry.thread_id.compare_exchange_strong(
            expected, thread_id, std::memory_order_relaxed);
        if (success)
        {
          return &table_[indexToTest];
        }
        // Ignore the CAS failure since the entry must be populated,
        // just move on to the next entry.
      }
    }
    ReclaimOldEntries();
  }
}

bool EpochManager::MinEpochTable::IsProtected()
{
  Entry *entry = nullptr;
  auto s = GetEntryForThread(&entry);
#ifdef TEST_BUILD
  CHECK_EQ(s, true);
#endif
  // It's myself checking my own protected_epoch, safe to use relaxed
  return entry->protected_epoch.load(std::memory_order_relaxed) != 0;
}

void EpochManager::MinEpochTable::ReleaseEntryForThread() {}

void EpochManager::MinEpochTable::ReclaimOldEntries() {}
