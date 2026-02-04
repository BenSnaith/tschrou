#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <string>
#include <expected>

namespace tsc::type {
// rust like types
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using u128 = __uint128_t;

using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;
using i128 = __int128_t;

using NodeID = u32;
using KeyID = u32;

template<typename T>
using Result = std::expected<T, std::string>;

using KeySet = std::vector<std::pair<std::string, std::string>>;

// number of bits in the identifier space.
// 32-bits will give us 4 billion possible ID's
// the original chord paper uses 160 bits for identifier
// space however this is overkill for the project and would
// require too much compute to even demonstrate.
constexpr int kMBits = u32;
constexpr int kMaxID = UINT32_MAX;

struct NodeAddress {
  bool operator==(const NodeAddress& other) const {
    return ip_ == other.ip_ && port_ == other.port_;
  }

  bool operator!=(const NodeAddress& other) const {
    return !(*this == other);
  }

  [[nodiscard]] std::string ToString() const {
    return ip_ + std::to_string(port_);
  }

  std::string ip_;
  u16 port_;
};

struct NodeInfo {
  bool operator==(const NodeInfo& other) const {
    return id_ == other.id_ && address_ == other.address_;
  }

  bool operator!=(const NodeInfo& other) const {
    return !(*this == other);
  }

  [[nodiscard]] bool IsValid() const {
    return !address_.ip_.empty() && address_.port_ > 0;
  }

  NodeID id_;
  NodeAddress address_;
};

inline bool InRangeExclusive(NodeID id, NodeID start, NodeID end) {
  if (start == end) {
    return id != start;
  }
  if (start < end) {
    return id > start && id < end;
  } else {
    return id > start || id < end;
  }
}

inline bool InRangeExclusiveInclusive(NodeID id, NodeID start, NodeID end) {
    if (start < end) {
        // Normal case: no wraparound
        return id > start && id <= end;
    }
    if (start > end) {
        // Wraparound case
        return id > start || id <= end;
    }
    return true;
}
} // namespace tsc::type

#endif TYPES_H