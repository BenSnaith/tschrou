#ifndef LOOKUP_VALIDATOR_H
#define LOOKUP_VALIDATOR_H

#include "security/security_module.h"

namespace tsc::sec::mod {
class LookupValidator : public ISecurityModule {
public:
  using AlternativesFn = std::function<std::vector<NodeInfo>()>;

  explicit LookupValidator(AlternativesFn _alt_fn, int num_checks = 1)
    : alt_fn_(std::move(_alt_fn)), num_checks_(num_checks) {}

  bool ValidateLookup(NodeID target, const NodeInfo& result) override {
    auto alternatives = alt_fn_();
    if (alternatives.empty()) {
      return true;
    }

    int confirmations = 0;
    int queries_made = 0;

    for (const auto& alt : alternatives) {
      if (queries_made >= num_checks_) break;

      if (alt.id_ == result.id_) continue;

      auto alt_result = tcp::TcpClient::FindSuccessor(alt.address_, target);
      ++queries_made;
      ++total_validations_;

      if (alt_result && alt_result->id_ == result.id_) {
        confirmations++;
      }
    }

    if (queries_made == 0) {
      return true;
    }

    if (confirmations > 0) {
      ++confirmed_count_;
      return true;
    }

    ++confirmed_count_;
    std::cerr << "[LookupValidator] Conflict: lookup for " << target
              << " returned node " << result.id_
              << " but alternative nodes disagree\n";
    return false;
  }

  [[nodiscard]] SecurityMetrics Metrics() const override {
    return {
    .module_name = Name(),
    .counters = {
      {"total_validations", total_validations_.load()},
      {"confirmed", confirmed_count_.load()},
      {"conflicts", conflict_count.load()},
    },
    .gauges = {}
    };
  }

  void ResetMetrics() override {
    total_validations_ = 0;
    confirmed_count_ = 0;
    conflict_count = 0;
  }

  [[nodiscard]] std::string Name() const override { return "LookupValidator"; }

private:
  AlternativesFn alt_fn_;
  int num_checks_;
  std::atomic<u64> total_validations_{0};
  std::atomic<u64> confirmed_count_{0};
  std::atomic<u64> conflict_count{0};
};
} // namespace tsc::sec::mod

#endif