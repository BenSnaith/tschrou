#ifndef HONEYPOT_MONITOR_H
#define HONEYPOT_MONITOR_H

#include <functional>


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


  std::string Name() const override { return "HoneypotMonitor"; }

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