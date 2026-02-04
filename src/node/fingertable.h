#ifndef FINGERTABLE_H
#define FINGERTABLE_H

#include <array>
#include <optional>
#include <mutex>

#include "types/types.h"

namespace tsc::node {
using namespace tsc::type;
class FingerTable {
public:
  explicit FingerTable(NodeID owner_id);

  [[nodiscard]] std::optional<NodeInfo> Get(int index) const;

  void Set(int index, const NodeInfo& node);

  void Clear(int index);

  [[nodiscard]] NodeID GetStart(int index) const;

  [[nodiscard]] std::optional<NodeInfo> ClosestPrecedingNode(NodeID id) const;

  void InitialiseTo(const NodeInfo& node);

  void Print() const;

  static constexpr int kSize = kMBits;

private:
  NodeID owner_id_;
  std::array<std::optional<NodeInfo>, kSize> fingers_;
  mutable std::mutex mutex_;
};
} // namespace tsc::node

#endif FINGERTABLE_H