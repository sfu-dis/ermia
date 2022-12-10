#pragma once
#include <x86intrin.h>
#include <cassert>
#include "epoch_manager.h"

/// Interface for the GarbageList; used to make it easy to drop is mocked out
/// garbage lists for unit testing. See GarbageList template below for
/// full documentation.
class IGarbageList
{
public:
  typedef void (*DestroyCallback)(void *callback_context, void *object);

  IGarbageList() {}

  virtual ~IGarbageList() {}

  virtual bool Initialize(EpochManager *epoch_manager,
                          size_t size = 4 * 1024 * 1024)
  {
    (epoch_manager);
    (size);
    return true;
  }

  virtual bool Uninitialize() { return true; }

  virtual bool Push(void *removed_item, DestroyCallback destroy_callback,
                    void *context) = 0;
};

/// Tracks items that have been removed from a data structure but to which
/// there may still be concurrent accesses using the item from other threads.
/// GarbageList works together with the EpochManager to ensure that items
/// placed on the list are only destructed and freed when it is safe to do so.
///
/// Lock-free data structures use this template by creating an instance specific
/// to the type of the item they will place on the list. When an element is
/// has been "removed" from the data structure it should call Push() to
/// transfer responsibility for the item over to the garbage list.
/// Occasionally, Push() operations will check to see if objects on the list are
/// ready for reuse, freeing them up if it is safe to do so. The user of the
/// GarbageList provides a callback that is invoked so custom logic can be used
/// to reclaim resources.
class GarbageList : public IGarbageList
{
public:
  /// Holds a pointer to an object in the garbage list along with the Epoch
  /// in which it was removed and a chain field so that it can be linked into
  /// a queue.
  struct Item
  {
    /// Epoch in which the #m_removedItem was removed from the data
    /// structure. In practice, due to delay between the actual removal
    /// operation and the push onto the garbage list, #m_removalEpoch may
    /// be later than when the actual remove happened, but that is safe
    /// since the invariant is that the epoch stored here needs to be
    /// greater than or equal to the current global epoch in which the
    /// item was actually removed.
    Epoch removal_epoch;

    /// Function provided by user on Push() called when an object
    /// that was pushed to the list is safe for reclamation. When invoked the
    /// function is passed a pointer to an object that is safe to destroy and
    /// free along with #m_pbDestroyCallbackContext. The function must
    /// perform all needed destruction and release any resources associated
    /// with the object.
    DestroyCallback destroy_callback;

    /// Passed along with a pointer to the object to destroy to
    /// #m_destroyCallback; it threads state to destroyCallback calls so they
    /// can access, for example, the allocator from which the object was
    /// allocated.
    void *destroy_callback_context;

    /// Point to the object that is enqueued for destruction. Concurrent
    /// accesses may still be ongoing to the object, so absolutely no
    /// changes should be made to the value it refers to until
    /// #m_removalEpoch is deemed safe for reclamation by the
    /// EpochManager.
    void *removed_item;

    /// Used to get back the item based on the mem provided.
    static Item *GetItemFromRemoved(void *mem)
    {
      return reinterpret_cast<Item *>((char *)mem - 24);
    }

    void SetValue(void *removed_item, Epoch epoch, DestroyCallback callback,
                  void *context)
    {
      assert(this->removal_epoch == invalid_epoch);

      this->destroy_callback = callback;
      this->destroy_callback_context = context;
      this->removed_item = removed_item;
      this->removal_epoch = epoch;
    }
  };
  static_assert(std::is_pod<Item>::value, "Item should be POD");
  static const constexpr uint64_t invalid_epoch = ~0llu;

  /// Construct a GarbageList in an uninitialized state.
  GarbageList() : epoch_manager_{}, tail_{}, item_count_{}, items_{} {}

  /// Uninitialize the GarbageList (if still initialized) and destroy it.
  virtual ~GarbageList() { Uninitialize(); }

  /// Initialize the GarbageList and associate it with an EpochManager.
  /// This must be called on a newly constructed instance before it
  /// is safe to call other methods. If the GarbageList is already
  /// initialized then it will have no effect.
  ///
  /// \param pEpochManager
  ///      EpochManager that is used to determine when it is safe to reclaim
  ///      items pushed onto the list. Must not be nullptr.
  /// \param nItems
  ///      Number of addresses that can be held aside for pointer stability.
  ///      If this number is too small the system runs the risk of deadlock.
  ///      Must be a power of two.
  ///
  /// \retval S_OK
  ///      The instance is now initialized and ready for use.
  /// \retval S_FALSE
  ///      The instance was already initialized; no effect.
  /// \retval E_INVALIDARG
  ///      \a nItems wasn't a power of two.

#ifdef PMEM
  virtual bool Initialize(EpochManager *epoch_manager, PMEMobjpool *pool_,
                          size_t item_count = 128 * 1024)
  {
#else
  virtual bool Initialize(EpochManager *epoch_manager,
                          size_t item_count = 128 * 1024)
  {
#endif
    if (epoch_manager_)
      return true;

    if (!epoch_manager)
      return false;

    if (!item_count || !IS_POWER_OF_TWO(item_count))
    {
      return false;
    }

    size_t nItemArraySize = sizeof(*items_) * item_count;

#ifdef PMEM
    // TODO(hao): better error handling
    PMEMoid ptr;
    TX_BEGIN(pool_)
    {
      // Every PMDK allocation so far will pad to 64 cacheline boundry.
      // To prevent memory leak, pmdk will chain the allocations by adding a
      // 16-byte pointer at the beginning of the requested memory, which breaks
      // the memory alignment. the PMDK_PADDING is to force pad again
      pmemobj_zalloc(pool_, &ptr, nItemArraySize + very_pm::kPMDK_PADDING,
                     TOID_TYPE_NUM(char));
      items_ = (GarbageList::Item *)((char *)pmemobj_direct(ptr) +
                                     very_pm::kPMDK_PADDING);
    }
    TX_END
#else
    posix_memalign((void **)&items_, 64, nItemArraySize);
#endif

    if (!items_)
      return false;

    for (size_t i = 0; i < item_count; ++i)
      new (&items_[i]) Item{};

    item_count_ = item_count;
    tail_ = 0;
    epoch_manager_ = epoch_manager;

    return true;
  }

  /// Uninitialize the GarbageList and disassociate from its EpochManager;
  /// for each item still on the list call its destructor and free it.
  /// Careful: objects freed by this call will NOT obey the epoch protocol,
  /// so it is important that this thread is only called when it is clear
  /// that no other threads may still be concurrently accessing items
  /// on the list.
  ///
  /// \retval S_OK
  ///      The instance is now uninitialized; resources were released.
  /// \retval S_FALSE
  ///      The instance was already uninitialized; no effect.
  virtual bool Uninitialize()
  {
    if (!epoch_manager_)
      return true;

    for (size_t i = 0; i < item_count_; ++i)
    {
      Item &item = items_[i];
      if (item.removed_item)
      {
        item.destroy_callback(item.destroy_callback_context, item.removed_item);
        item.removed_item = nullptr;
        item.removal_epoch = 0;
      }
    }

#ifdef PMEM
    auto oid = pmemobj_oid((char *)items_ - very_pm::kPMDK_PADDING);
    pmemobj_free(&oid);
#else
    delete items_;
#endif

    items_ = nullptr;
    tail_ = 0;
    item_count_ = 0;
    epoch_manager_ = nullptr;

    return true;
  }

  /// Append an item to the reclamation queue; the item will be stamped
  /// with an epoch and will not be reclaimed until the EpochManager confirms
  /// that no threads can ever access the item again. Once an item is ready
  /// for removal the destruction callback passed to Initialize() will be
  /// called which must free all resources associated with the object
  /// INCLUDING the memory backing the object.
  ///
  /// \param removed_item
  ///      Item to place on the list; it will remain live until
  ///      the EpochManager indicates that no threads will ever access it
  ///      again, after which the destruction callback will be invoked on it.
  /// \param callback
  ///      Function to call when the object that was pushed to the list is safe
  ///      for reclamation. When invoked the, function is passed a pointer to
  ///      an object that is safe to destroy and free along with
  ///      \a pvDestroyCallbackContext. The function must perform
  ///      all needed destruction and release any resources associated with
  ///      the object. Must not be nullptr.
  /// \param context
  ///      Passed along with a pointer to the object to destroy to
  ///      \a destroyCallback; it threads state to destroyCallback calls so
  ///      they can access, for example, the allocator from which the object
  ///      was allocated. Left uninterpreted, so may be nullptr.
  virtual bool Push(void *removed_item, DestroyCallback callback,
                    void *context)
  {
    Epoch removal_epoch = epoch_manager_->GetCurrentEpoch();

    for (;;)
    {
      int64_t slot = (tail_.fetch_add(1) - 1) & (item_count_ - 1);

      // Everytime we work through 25% of the capacity of the list roll
      // the epoch over.
      if (((slot << 2) & (item_count_ - 1)) == 0)
        epoch_manager_->BumpCurrentEpoch();

      Item &item = items_[slot];

      Epoch priorItemEpoch = item.removal_epoch;
      if (priorItemEpoch == invalid_epoch)
      {
        // Someone is modifying this slot. Try elsewhere.
        continue;
      }

      Epoch result = CompareExchange64<Epoch>(&item.removal_epoch,
                                              invalid_epoch, priorItemEpoch);
      if (result != priorItemEpoch)
      {
        // Someone else is now modifying the slot or it has been
        // replaced with a new item. If someone replaces the old item
        // with a new one of the same epoch number, that's ok.
        continue;
      }

      // Ensure it is safe to free the old entry.
      if (priorItemEpoch)
      {
        if (!epoch_manager_->IsSafeToReclaim(priorItemEpoch))
        {
          // Uh-oh, we couldn't free the old entry. Things aren't looking
          // good, but maybe it was just the result of a race. Replace the
          // epoch number we mangled and try elsewhere.
          *((volatile Epoch *)&item.removal_epoch) = priorItemEpoch;
          continue;
        }
        item.destroy_callback(item.destroy_callback_context, item.removed_item);
      }

      Item stack_item;
      stack_item.destroy_callback = callback;
      stack_item.destroy_callback_context = context;
      stack_item.removed_item = removed_item;
      *((volatile Epoch *)&stack_item.removal_epoch) = removal_epoch;

#ifdef PMEM
      auto value = _mm256_set_epi64x((int64_t)removed_item, (int64_t)context,
                                     (int64_t)callback, (int64_t)removal_epoch);
      _mm256_stream_si256((__m256i *)(items_ + slot), value);
#else
      items_[slot] = stack_item;
#endif
      return true;
    }
  }

  /// Used to reserve a place for (persistent memory) allocators that requires a
  /// pre-existing memory location. The corresponding removal_epoch will be
  /// marked as invalid epoch.
  Item *ReserveItem()
  {
    Epoch removal_epoch = epoch_manager_->GetCurrentEpoch();
    for (;;)
    {
      int64_t slot = (tail_.fetch_add(1) - 1) & (item_count_ - 1);

      // Everytime we work through 25% of the capacity of the list roll
      // the epoch over.
      if (((slot << 2) & (item_count_ - 1)) == 0)
        epoch_manager_->BumpCurrentEpoch();

      Item &item = items_[slot];
      Epoch priorItemEpoch = item.removal_epoch;

      Epoch result = CompareExchange64<Epoch>(&item.removal_epoch,
                                              invalid_epoch, priorItemEpoch);
      if (result != priorItemEpoch)
      {
        // Someone else is now modifying the slot or it has been
        // replaced with a new item. If someone replaces the old item
        // with a new one of the same epoch number, that's ok.
        continue;
      }

      // Ensure it is safe to free the old entry.
      if (priorItemEpoch)
      {
        if (!epoch_manager_->IsSafeToReclaim(priorItemEpoch))
        {
          // Uh-oh, we couldn't free the old entry. Things aren't looking
          // good, but maybe it was just the result of a race. Replace the
          // epoch number we mangled and try elsewhere.
          *((volatile Epoch *)&item.removal_epoch) = priorItemEpoch;
          continue;
        }
        item.destroy_callback(item.destroy_callback_context, item.removed_item);
      }
      return &item;
    }
  }

  /// The counterpart of ReserveMemory, used to reset the item so that the item
  /// can be reused and the corresponding memory won't be recliamed on recovery
  bool ResetItem(Item *item)
  {
    auto old_epoch = item->removal_epoch;
    assert(old_epoch == invalid_epoch);
    item->removal_epoch = 0;
    item->removed_item = nullptr;
    return true;
  }

#ifdef PMEM
  /// Recover the grabage list from a user specified location
  /// Scan all the items in the larbage list, if any item that is not nullptr,
  /// we call the destroy callback.
  bool Recovery(EpochManager *epoch_manager, PMEMobjpool *pmdk_pool)
  {
    uint32_t reclaimed{0};
    for (size_t i = 0; i < item_count_; ++i)
    {
      Item &item = items_[i];
      if (item.removed_item != nullptr)
      {
        item.destroy_callback(item.destroy_callback_context, item.removed_item);
        new (&items_[i]) Item{};
        reclaimed += 1;
      }
    }
#ifdef TEST_BUILD
    LOG(INFO) << "[Garbage List]: reclaimed " << reclaimed << " items."
              << std::endl;
#endif
    tail_ = 0;
    epoch_manager_ = epoch_manager;
    pmdk_pool_ = pmdk_pool;
    return true;
  }
#endif

  /// Scavenge items that are safe to be reused - useful when the user cannot
  /// wait until the garbage list is full. Currently (May 2016) the only user is
  /// MwCAS' descriptor pool which we'd like to keep small. Tedious to tune the
  /// descriptor pool size vs. garbage list size, so there is this function.
  int32_t Scavenge()
  {
    auto max_slot = tail_.load(std::memory_order_relaxed);
    int32_t scavenged = 0;

    for (int64_t slot = 0; slot < item_count_; ++slot)
    {
      auto &item = items_[slot];
      Epoch priorItemEpoch = item.removal_epoch;
      if (priorItemEpoch == 0 || priorItemEpoch == invalid_epoch)
      {
        // Someone is modifying this slot. Try elsewhere.
        continue;
      }

      Epoch result = CompareExchange64<Epoch>(&item.removal_epoch,
                                              invalid_epoch, priorItemEpoch);
      if (result != priorItemEpoch)
      {
        // Someone else is now modifying the slot or it has been
        // replaced with a new item. If someone replaces the old item
        // with a new one of the same epoch number, that's ok.
        continue;
      }

      if (priorItemEpoch)
      {
        if (!epoch_manager_->IsSafeToReclaim(priorItemEpoch))
        {
          // Uh-oh, we couldn't free the old entry. Things aren't looking
          // good, but maybe it was just the result of a race. Replace the
          // epoch number we mangled and try elsewhere.
          *((volatile Epoch *)&item.removal_epoch) = priorItemEpoch;
          continue;
        }
        item.destroy_callback(item.destroy_callback_context, item.removed_item);
      }

      // Now reset the entry
      Item stack_item;
      stack_item.destroy_callback = nullptr;
      stack_item.destroy_callback_context = nullptr;
      stack_item.removed_item = nullptr;
      *((volatile Epoch *)&stack_item.removal_epoch) = 0;
#ifdef PMEM
      auto value =
          _mm256_set_epi64x((int64_t)0, (int64_t)0, (int64_t)0, (int64_t)0);
      _mm256_stream_si256((__m256i *)(items_ + slot), value);
#else
      items_[slot] = stack_item;
#endif
    }

    return scavenged;
  }

  /// Returns (a pointer to) the epoch manager associated with this garbage
  /// list.
  EpochManager *GetEpoch() { return epoch_manager_; }

private:
#ifdef TEST_BUILD
  FRIEND_TEST(GarbageListPMTest, ReserveMemory);
#endif
  /// EpochManager instance that is used to determine when it is safe to
  /// free up items. Specifically, it is used to stamp items during Push()
  /// with the current epoch, and it is used in to ensure
  /// that deletion of each item on the list is safe.
  EpochManager *epoch_manager_;

  /// Point in the #m_items ring where the next pushed address will be placed.
  /// Also indicates the next address that will be freed on the next push.
  /// Atomically incremented within Push().
  std::atomic<int64_t> tail_;

  /// Size of the #m_items array. Must be a power of two.
  size_t item_count_;

  /// Ring of addresses the addresses pushed to the list and metadata about
  /// them needed to determine when it is safe to free them and how they
  /// should be freed. This is filled as a ring; when a new Push() comes that
  /// would replace an already occupied slot the entry in the slot is freed,
  /// if possible.
  Item *items_;

#ifdef PMEM
  PMEMobjpool *pmdk_pool_;
#endif
};
