#ifndef ID_VERIFICATION_H
#define ID_VERIFICATION_H

#include "security/security_module.h"
#include "util/hash.h"

namespace tsc::sec::mod {
class IDVerification : public ISecurityModule {
public:
  bool AllowNode(const NodeInfo& node) override {
    NodeID expected = hsh::Hash::HashNode(node.address_);

    if (node.id_ != expected) {
      ++rejected_count_;
      std::cerr << "[IDVerify] Rejected node" << node.id_
                << " at " << node.address_.ToString()
                << " (expected ID " << expected << ")\n";
      return false;
    }

    ++accepted_count_;
    return true;
  }

  bool ValidateLookup(NodeID target, const NodeInfo& result) override {
    NodeID expected = hsh::Hash::HashNode(result.address_);
    if (result.id_ != expected) {
      ++lookup_rejections_;
      return false;
    }
    return true;
  }

  [[nodiscard]] SecurityMetrics Metrics() const override {
    return {
      .module_name = Name(),
      .counters = {
        {"accepted", accepted_count_.load()},
        {"rejected", rejected_count_.load()},
        {"lookup_rejections", lookup_rejections_.load()},
      },
      .gauges = {}
    };
  }

  void ResetMetrics() override {
    accepted_count_ = 0;
    rejected_count_ = 0;
    lookup_rejections_ = 0;
  }

  [[nodiscard]] std::string Name() const override { return "id_verification"; }

private:
  std::atomic<u64> accepted_count_{0};
  std::atomic<u64> rejected_count_{0};
  std::atomic<u64> lookup_rejections_{0};
};
} // namespace tsc::sec::mod

#endif