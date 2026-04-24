#ifndef SUBNET_DIVERSITY_H
#define SUBNET_DIVERSITY_H

#include <unordered_set>


#include "security/security_module.h"

namespace tsc::sec::mod {
class SubnetDiversity : public ISecurityModule {
public:
  explicit SubnetDiversity(int max_per_subnet = 2)
    : max_per_subnet_(max_per_subnet) {}

  bool AllowNode(const NodeInfo& node) override {
    std::string subnet = ExtractSubnet(node.address_.ip_);
    std::lock_guard lock(mutex_);
    auto& ids = subnet_counts_[subnet];

    if (ids.contains(node.id_)) {
      return true;
    }

    if (static_cast<int>(ids.size()) >= max_per_subnet_) {
      ++rejected_count_;
      over_limit_ids_.insert(node.id_);
      std::cerr << "[SubnetDiversity] Rejected node " << node.id_
                << " from subnet " << subnet
                << " (count " << ids.size() << " >= max " << max_per_subnet_
                << ")\n";
      return false;
    }

    ids.insert(node.id_);
    ++accepted_count_;
    return true;
  }

  bool PreferOver(const NodeInfo& incumbent,
                  const NodeInfo& candidate) override {
    std::lock_guard lock(mutex_);
    return over_limit_ids_.contains(candidate.id_)
           && !over_limit_ids_.contains(incumbent.id_);
  }

  void Tick() override {
    std::lock_guard lock(mutex_);
    auto it = subnet_counts_.begin();
    while (it != subnet_counts_.end()) {
      if (it->second.empty()) {
        it = subnet_counts_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void NodeRemoved(const NodeInfo& node) {
    std::string subnet = ExtractSubnet(node.address_.ip_);
    std::lock_guard lock(mutex_);
    auto it = subnet_counts_.find(subnet);
    if (it != subnet_counts_.end()) {
      it->second.erase(node.id_);
    }
  }

  SecurityMetrics Metrics() const override {
    std::lock_guard lock(mutex_);
    return {
    .module_name = Name(),
      .counters = {
        {"accepted", accepted_count_},
         {"rejected", rejected_count_},
      },
      .gauges = {
      {"unique_subnets", static_cast<double>(subnet_counts_.size())},
      }
    };
  }

  void ResetMetrics() override {
    std::lock_guard lock(mutex_);
    accepted_count_ = 0;
    rejected_count_ = 0;
    subnet_counts_.clear();
    over_limit_ids_.clear();
  }

  std::string Name() const override { return "SubnetDiversity"; }

private:
  static std::string ExtractSubnet(const std::string& ip) {
    auto last_dot = ip.rfind('.');
    if (last_dot == std::string::npos) return ip;
    return ip.substr(0, last_dot);
  }

  int max_per_subnet_{};
  std::unordered_map<std::string, std::unordered_set<NodeID>> subnet_counts_;
  std::unordered_set<NodeID> over_limit_ids_;
  mutable std::mutex mutex_;
  std::atomic<u64> accepted_count_{0};
  std::atomic<u64> rejected_count_{0};
};
} // namespace tsc::sec::mod

#endif