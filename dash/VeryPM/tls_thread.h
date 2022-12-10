#pragma once
#include <cstdint>
#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>

/// A wrapper for std::thread that bookkeeps C++11 thread_local variables to
/// handle thread/TLS variable interactions.  The key problem is avoding
/// leaving dangling pointers in TLS variables pointing to resource already
/// destroyed (e.g., a thread re-purposed to use another descriptor pool after
/// destroying a previous one in test cases).
///
/// Typical uses: client code instantiates threads just like using std::thread,
/// but whenever it initializes TLS variables that might need to avoid leaving
/// dangling pointers, use RegisterTls. Upon thread destruction/join, the TLS
/// variables are automatically reset using the default value provided through
/// RegisterTls.
///
/// In case of the same thread using different resources, e.g., descriptor pool,
/// the thread should invoke ClearRegistry to ensure all TLS variables do not
/// point to previously destroyed resources.
///
/// Here we keep it always the thread that resets its own TLS variables.
class Thread : public std::thread {
 public:
  /// Pairs of <pointer to variable, invalid value>, supports 8-byte word types
  /// only for now.
  typedef std::list<std::pair<uint64_t *, uint64_t> > TlsList;

  static std::unordered_map<std::thread::id, TlsList *> registry_;
  static std::mutex registryMutex_;

  template <typename... Args>
  Thread(Args &&... args)
      : std::thread(std::forward<Args>(args)...), id_(get_id()) {}
  ~Thread() { ClearTls(true); }

  /// Overrides std::thread's join
  inline void join() {
    std::thread::join();
    ClearTls();
  }

  /// Register a thread-local variable
  /// @ptr - pointer to the TLS variable
  /// @val - default value of the TLS variable
  static void RegisterTls(uint64_t *ptr, uint64_t val);

  /// Clear/reset the entire global TLS registry covering all threads
  static void ClearRegistry(bool destroy = false);

 private:
  /// Clear/reset the TLS variables of this thread
  void ClearTls(bool destroy = false);
  std::thread::id id_;
};

std::unordered_map<std::thread::id, Thread::TlsList *> Thread::registry_;
std::mutex Thread::registryMutex_;

void Thread::RegisterTls(uint64_t *ptr, uint64_t val) {
  auto id = std::this_thread::get_id();
  std::unique_lock<std::mutex> lock(registryMutex_);
  if (registry_.find(id) == registry_.end()) {
    registry_.emplace(id, new TlsList);
  }
  registry_[id]->emplace_back(ptr, val);
}

void Thread::ClearTls(bool destroy) {
  std::unique_lock<std::mutex> lock(registryMutex_);
  auto iter = registry_.find(id_);
  if (iter != registry_.end()) {
    auto *list = iter->second;
    for (auto &entry : *list) {
      *entry.first = entry.second;
    }
    if (destroy) {
      delete list;
      registry_.erase(id_);
    } else {
      list->clear();
    }
  }
}

void Thread::ClearRegistry(bool destroy) {
  std::unique_lock<std::mutex> lock(registryMutex_);
  for (auto &r : registry_) {
    auto *list = r.second;
    for (auto &entry : *list) {
      *entry.first = entry.second;
    }
    if (destroy) {
      delete list;
    } else {
      list->clear();
    }
  }
  if (destroy) {
    registry_.clear();
  }
}
