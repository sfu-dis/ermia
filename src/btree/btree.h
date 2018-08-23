#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace ermia {
namespace btree {

// Basic node type common to both internal and leaf nodes
class Node {
protected:
  uint32_t num_keys_;

public:
  Node() : num_keys_(0) {}
  inline uint32_t NumKeys() { return num_keys_; }
  virtual bool IsLeaf() = 0;
  virtual void Dump() = 0;
};

struct Stack {
  struct Frame {
    Node *node;
    Frame() : node(nullptr) {}
    Frame(Node *node) : node(node) {}
    ~Frame() { node = nullptr; }
  };

  static const uint32_t kMaxFrames = 32;
  Frame frames[kMaxFrames];
  uint32_t num_frames;

  Stack() : num_frames(0) {}
  ~Stack() { num_frames = 0; }
  inline void Push(Node *node) { new (&frames[num_frames++]) Frame(node); }
  inline Node *Pop() { return num_frames == 0 ? nullptr : frames[--num_frames].node; }
  Node *Top() { return num_frames == 0 ? nullptr : frames[num_frames - 1].node; }
};

// Key-value (or key-pointer) pair header stored in nodes. Value/pointer is
// supposed to follow the key string which is pointed to by [data_] which usually
// points to somewhere in the leaf/internal node's data area (alternatively it
// could be in the heap if data is too large).
class NodeEntry {
private:
  uint32_t key_size_;    // Key size
  uint32_t value_size_;  // Value size
  char *data_;           // Data (includes key and value) address

private:
  inline char *GetData() { return data_; }
  static int Compare(char *d1, uint32_t l1, char *d2, uint32_t l2) {
    int cmp = memcmp(d1, d2, std::min<uint32_t>(l1, l2));
    if (cmp == 0 && l1 != l2) {
      return l1 > l2 ? 1 : -1;
    }
    return cmp;
  }

public:
  NodeEntry() : key_size_(0), value_size_(0), data_(nullptr) {}
  NodeEntry(uint32_t key_size, uint32_t value_size, char *data, char *key, char *value)
    : key_size_(key_size), value_size_(value_size), data_(data) {
    memcpy(data_, key, key_size_);
    memcpy(data_ + key_size_, value, value_size_);
  }
  inline uint32_t GetKeySize() { return key_size_; }
  inline uint32_t GetValueSize() { return value_size_; }
  inline char *GetKeyData() { return data_; }
  inline char *GetValueData() { return data_ + key_size_; }

  inline int CompareKey(char *key, uint32_t size) {
    return NodeEntry::Compare(GetKeyData(), key_size_, key, size);
  }
};

// Leaf node header that contains size of the keys and values, and a pointer to
// the right sibling. Data (keys and values) must follow right after this struct.
//
// DataEntries grow 'downwards' and key-value (actual data) pairs correspond to
// DataEntries grow 'upwards':
//
// -----------------------------------------
// num_keys_ | data_size_ | right_sibling_ |
// -----------------------------------------
// NodeEntry 1 | NodeEntry 2 | NodeEntry 3 |
// -----------------------------------------
//        ... more NodeEntries ...
// -----------------------------------------
//               free space
// -----------------------------------------
//  more key-value pairs | Key 3 + value 3 |
// -----------------------------------------
//     Key 2 + value 2  |  Key 1 + value 1 |
// -----------------------------------------
template<uint32_t NodeSize, class PayloadType>
class LeafNode : public Node {
private:
  uint32_t data_size_;  // Includes keys and values, not including the NodeEntry array
  LeafNode *right_sibling_;
  char data_[0];  // Must be the last element

private:
  void InsertAt(uint32_t idx, char *key, uint32_t key_size, PayloadType &payload);
  void Split(LeafNode *&left, LeafNode *&right, Stack &stack);
  inline NodeEntry &GetEntry(uint32_t idx) { return ((NodeEntry *)data_)[idx]; }

public:
  LeafNode() : Node(), data_size_(0), right_sibling_(nullptr) {}
  inline bool IsLeaf() override { return true; }
  NodeEntry *GetEntry(char *key, uint32_t key_size);

  static LeafNode *New() {
    LeafNode *node = (LeafNode *)malloc(NodeSize);
    new (node) LeafNode();
    return node;
  }

  // Data area size, including keys and values
  inline uint32_t DataCapacity() {
    return NodeSize - sizeof(*this) - num_keys_ * sizeof(NodeEntry);
  }
  inline void SetRightSibling(LeafNode *node) { right_sibling_ = node; }
  inline LeafNode *GetRightSibling() { return right_sibling_; }
  inline char *GetKey(uint32_t idx) { return GetEntry(idx).GetKeyData(); }
  inline char *GetValue(uint32_t idx) { return GetEntry(idx).GetValueData(); }
  bool Add(char *key, uint32_t key_size, PayloadType &payload, bool &did_split, Stack &stack);
  void Dump() override {}
};

// Internal node that contains keys and pointers to right children nodes, and a
// pointer to the left-most child. Data (keys and pointers) must follow right after
// this struct.
//
// DataEntries grow 'downwards' and key-pointer (actual data) pairs correspond to
// DataEntries grow 'upwards':
//
// -----------------------------------------
// num_keys_ |   min_ptr_   |  data_size_  |
// -----------------------------------------
// NodeEntry 1 | NodeEntry 2 | NodeEntry 3 |
// -----------------------------------------
//        ... more NodeEntries ...
// -----------------------------------------
//               free space
// -----------------------------------------
//  more key-value pairs | Key 3 + value 3 |
// -----------------------------------------
//     Key 2 + value 2  |  Key 1 + value 1 |
// -----------------------------------------

template<uint32_t NodeSize>
class InternalNode : public Node {
private:
  Node *min_ptr_;  // Left-most child
  uint32_t data_size_;  // Includes keys only, pointers are stored in InternalEntries
  char data_[0];  // Must be the last element

private:
  void InsertAt(uint32_t idx, char *key, uint32_t key_size, Node *left_child, Node *right_child);
  void Split(InternalNode *&left, InternalNode *&right, Stack &stack);

public:
  InternalNode() : min_ptr_(nullptr), data_size_(0) {}
  inline bool IsLeaf() override { return false; }
  inline uint32_t DataCapacity() {
    return NodeSize - sizeof(*this) - num_keys_ * sizeof(NodeEntry);
  }
  inline NodeEntry &GetEntry(uint32_t idx) { return ((NodeEntry *)data_)[idx]; }
  Node *GetChild(char *key, uint32_t key_size);
  static inline InternalNode *New() {
    InternalNode<NodeSize> *node = (InternalNode *)malloc(NodeSize);
    new (node) InternalNode<NodeSize>;
    return node;
  }
  void Add(char *key, uint32_t key_size, Node *left_child, Node *right_child, bool &did_split, Stack &stack);
  Node *MinPtr() { return min_ptr_; }
  void Dump() override;
};

template<uint32_t NodeSize, class PayloadType>
class BTree {
private:
  Node *root_;

private:
  LeafNode<NodeSize, PayloadType> *ReachLeaf(char *key, uint32_t key_size, Stack &stack);

public:
  BTree() : root_(LeafNode<NodeSize, PayloadType>::New()) {}
  bool Insert(char *key, uint32_t key_size, PayloadType &payload);
  bool Search(char *key, uint32_t key_size, PayloadType *payload);
  void Dump();
};
}  // namespace btree
}  // namespace ermia
