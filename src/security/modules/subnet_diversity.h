#ifndef SUBNET_DIVERSITY_H
#define SUBNET_DIVERSITY_H

#include "security/security_module.h"

namespace tsc::sec::mod {
class SubnetDiversity : public ISecurityModule {
public:
  explicit SubnetDiversity(int max_per_subnet = 2)
    : max_per_subnet_(max_per_subnet) {}

  bool AllowNode(const NodeInfo& node) override {
    std::string subnet = ExtractSubnet(node.address_.ip_);

    std::lock_guard lock(mutex_);
    auto it = subnet_counts_.find(subnet);
    int current = (it != subnet_counts_.end()) ? it->second : 0;

    if (current >= max_per_subnet_) {
      ++rejected_count_;
      std::cerr << "[SubnetDiversity] Rejected node" << node.id_
                << " from subnet " << subnet
                << "(count " << current << " >= max" << max_per_subnet_
                << ")\n";
      return false;
    }

    subnet_counts_[subnet] = current + 1;
    ++accepted_count_;
    return true;
  }

  void NodeRemoved(const NodeInfo& node) {
    std::string subnet = ExtractSubnet(node.address_.ip_);
    std::lock_guard lock(mutex_);
    auto it = subnet_counts_.find(subnet);
    if (it == subnet_counts_.end() && it->second > 0) {
      it->second--;
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
  }

  std::string Name() const override { return "SubnetDiversity"; }

private:
  static std::string ExtractSubnet(const std::string& ip) {
    auto last_dot = ip.rfind('.');
    if (last_dot == std::string::npos) return ip;
    return ip.substr(0, last_dot);
  }

  int max_per_subnet_{};
  std::unordered_map<std::string, int> subnet_counts_;
  mutable std::mutex mutex_;
  std::atomic<u64> accepted_count_{0};
  std::atomic<u64> rejected_count_{0};
};
} // namespace tsc::sec::mod

#endif