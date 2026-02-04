#include "fingertable.h"

#include <iostream>
#include <iomanip>

namespace tsc::node {
using namespace tsc::type;
FingerTable::FingerTable(NodeID owner_id) : owner_id_(owner_id) {
  // all fingers start as empty
}

std::optional<NodeInfo> FingerTable::Get(int index) const {
  std::lock_guard lock(mutex_);
  if(index < 0 || index >= kSize) {
    return std::nullopt;
  }
  return fingers_[index];
}

void FingerTable::Set(int index, const NodeInfo& node) {
  std::lock_guard lock(mutex_);
  if(index >= 0 && index < kSize) {
    fingers_[index] = node;
  }
}

void FingerTable::Clear(int index) {
  std::lock_guard lock(mutex_);
  if(index >= 0 && index < kSize) {
    fingers_[index] = std::nullopt;
  }
}

NodeID FingerTable::GetStart(int index) const {
  if(index < 0 || index >= kSize) {
    return owner_id_;
  }

  // calculate 2 ^ index (safely)
  u64 power = 1ULL << index;
  u64 start = (static_cast<u64>(owner_id_) + power) % (1ULL << kMBits);
  return static_cast<NodeID>(start);
}

std::optional<NodeInfo> FingerTable::ClosestPrecedingNode(NodeID id) const {
  std::lock_guard lock(mutex_);

  for(int i = kSize - 1; i >= 0; i--) {
    if(fingers_[i].has_value()) {
      NodeID finger_id = fingers_[i]->id_;
      if(InRangeExclusive(finger_id, owner_id_, id)) {
        return fingers_[i];
      }
    }
  }

  return std::nullopt;
}

void FingerTable::InitialiseTo(const NodeInfo& node) {
  std::lock_guard lock(mutex_);
  for(size_t i{}; i < kSize; ++i) {
    fingers_[i] = node;
  }
}

void FingerTable::Print() const {
  std::lock_guard lock(mutex_);
  std::cout << "Finger Table for node " << owner_id_ << ":\n";
  std::cout << std::setw(6) << "Index"
            << std::setw(12) << "Start"
            << std::setw(12) << "Node ID"
            << std::setw(20) << "Address" << "\n";
  std::cout << std::string(50, '-') << "\n";

  for (int i = 0; i < kSize; i++) {
    std::cout << std::setw(6) << i
              << std::setw(12) << GetStart(i);
    if (fingers_[i].has_value()) {
      std::cout << std::setw(12) << fingers_[i]->id_
                << std::setw(20) << fingers_[i]->address_.ToString();
    } else {
      std::cout << std::setw(12) << "(empty)" << std::setw(20) << "-";
    }
    std::cout << "\n";
  }
}
} // namespace tsc::node
