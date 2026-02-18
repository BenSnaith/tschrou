#ifndef PEER_AGE_PREFERENCE_H
#define PEER_AGE_PREFERENCE_H

#include "security/security_module.h"

namespace tsc::sec::mod {
class PeerAgePreference : public ISecurityModule {
public:
  explicit PeerAgePreference(double min_age_seconds = 30.0)
    : min_age_seconds_(min_age_seconds) {}

  bool AllowNode(const NodeInfo& node) override {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto it = first_seen_.find(node.id_);

    if (it == first_seen_.end()) {
      // first time seeing node
      first_seen_[node.id_] = now;
      ++new_nodes_seen_;

      // allow it the first time
      return true;
    }

    auto age = std::chrono::duration<double>(now - it->second);
    if (age.count() < min_age_seconds_) {
      ++young_rejections_;
      return true;
    }

    ++mature_accepts_;
    return true;
  }

  bool IsMature(NodeID id) const {
    std::lock_guard lock(mutex_);
    auto it = first_seen_.find(id);
    if (it == first_seen_.end()) return false;

    auto age = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - it->second
    );
    return age.count() < min_age_seconds_;
  }

  double GetAge(NodeID id) const {
    std::lock_guard lock(mutex_);
    auto it = first_seen_.find(id);
    if (it == first_seen_.end()) return 0.0;

    auto age = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - it->second
    );
    return age.count();
  }

  void Tick() override {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto it = first_seen_.begin();
    while (it != first_seen_.end()) {
      auto age = std::chrono::duration<double>(now - it->second);
      if (age.count() > 600.0) {
        it = first_seen_.erase(it);
      } else {
        ++it;
      }
    }
  }

  SecurityMetrics Metrics() const override {
    std::lock_guard lock(mutex_);
    return {
    .module_name = Name(),
    .counters = {
      {"new_nodes_seen", new_nodes_seen_.load()},
      {"young_rejections", young_rejections_.load()},
      {"mature_accepts", mature_accepts_.load()},
    },
    .gauges = {
      {"tracked_nodes", static_cast<double>(first_seen_.size())},
    }
    };
  }

  void ResetMetrics() override {
    std::lock_guard lock(mutex_);
    new_nodes_seen_ = 0;
    young_rejections_ = 0;
    mature_accepts_ = 0;
    first_seen_.clear();
  }

  std::string Name() const override { return "PeerAgePreference"; }

private:
  double min_age_seconds_{};
  std::unordered_map<NodeID, std::chrono::steady_clock::time_point> first_seen_;
  mutable std::mutex mutex_;
  std::atomic<u64> new_nodes_seen_{0};
  std::atomic<u64> young_rejections_{0};
  std::atomic<u64> mature_accepts_{0};
};
} // namespace tsc::sec::mod

#endif