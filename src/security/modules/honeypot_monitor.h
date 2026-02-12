#ifndef HONEYPOT_MONITOR_H
#define HONEYPOT_MONITOR_H

#include <functional>
#include <iostream>


#include "security/security_module.h"

namespace tsc::sec::mod {
class HoneypotMonitor : public ISecurityModule {
public:
  struct Sentinel {
    std::string key;
    std::string value;
  };

  using GetFn = std::function<std::optional<std::string>(const std::string&)>;
  using PutFn = std::function<bool(const std::string&, const std::string&)>;

  HoneypotMonitor(GetFn get_fn, PutFn put_fn, int num_sentinels = 10)
    : get_fn_(std::move(get_fn))
    , put_fn_(std::move(put_fn))
  {
    for (int i = 0; i < num_sentinels; ++i) {
      sentinels_.push_back({
        .key = "__honeypot_" + std::to_string(i),
        .value = "sentinel_value_" + std::to_string(i)
      });
    }
  }

  void PlaceSentinels() {
    for (const auto& sentinel : sentinels_) {
      if (put_fn_(sentinel.key, sentinel.value)) {
        ++placed_count_;
      }
      else {
        std::cerr << "[Honeypot] Failed to place sentinel: " << sentinel.key << '\n';
      }
    }
    std::cout << "[Honeypot] Placed << " << placed_count_.load()
    << "/" << sentinels_.size() << '\n';
  }

  void Tick() override {
    VerifySentinels();
  }

  void VerifySentinels() {
    for (const auto& sentinel : sentinels_) {
      ++checks_count_;

      auto res = get_fn_(sentinel.key);
      if (res && *res == sentinel.value) {
        ++success_count_;
      }
      else if (res) {
        ++tampered_count_;
        std::cerr << "[Honeypot] Tampered:\nKey:" << sentinel.key
        << "\nValue:" << sentinel.value
        << "\nGot: " << *res << '\n';
      }
      else {
        ++failure_count_;
      }
    }
  }

  [[nodiscard]] SecurityMetrics Metrics() const override {
    u64 checks = checks_count_.load();
    u64 successes = success_count_.load();

    double ratio = (checks > 0)
    ? static_cast<double>(successes) / static_cast<double>(checks)
    : 1.0;

    return {
      .module_name = Name(),
      .counters = {
        {"placed", placed_count_.load()},
        {"checks", checks},
        {"successes", successes},
        {"failures", failure_count_.load()},
        {"tampered", tampered_count_.load()},
      },
      .gauges = {
        {"integrity_ratio", ratio},
      }
    };
  }

  void ResetMetrics() override {
    placed_count_ = 0;
    checks_count_ = 0;
    success_count_ = 0;
    failure_count_ = 0;
    tampered_count_ = 0;
  }

  [[nodiscard]] std::string Name() const override { return "HoneypotMonitor"; }

private:
  GetFn get_fn_;
  PutFn put_fn_;
  std::vector<Sentinel> sentinels_;

  std::atomic<u64> placed_count_{0};
  std::atomic<u64> checks_count_{0};
  std::atomic<u64> success_count_{0};
  std::atomic<u64> failure_count_{0};
  std::atomic<u64> tampered_count_{0};
};
} // namespace tsc::sec::mod

#endif