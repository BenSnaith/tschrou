#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include "security/security_module.h"

namespace tsc::sec::mod {
class RateLimiter : public ISecurityModule {
public:
  struct Config {
    int max_tokens = 50;
    double refill_rate = 10.0;
  };

  explicit RateLimiter(const Config& config = {}) : config_(config) {}

  bool AllowMessage(const NodeAddress& sender, MessageType type) override {
    // needed for liveness
    if (type == MessageType::kPing || type == MessageType::kPong) {
      return true;
    }

    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& bucket = buckets_[sender.ip_];

    // Initialise new bucket
    if (bucket.tokens < 0) {
      bucket.tokens = config_.max_tokens;
      bucket.last_refill = now;
    }

    // Refill tokens based on elapsed time
    auto elapsed = std::chrono::duration<double>(now - bucket.last_refill);
    bucket.tokens = std::min(
      static_cast<double>(config_.max_tokens),
      bucket.tokens + elapsed.count() * config_.refill_rate
    );
    bucket.last_refill = now;

    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      ++allowed_count_;
      return true;
    }

    ++throttled_count_;
    std::cerr << "[RateLimit] Throttled message from " << sender.ip_ << "\n";
    return false;
  }

  void Tick() override {
    // Prune stale buckets (nodes we haven't seen in 60s)
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto it = buckets_.begin();
    while (it != buckets_.end()) {
      auto age = std::chrono::duration<double>(now - it->second.last_refill);
      if (age.count() > 60.0) {
        it = buckets_.erase(it);
      } else {
        ++it;
      }
    }
  }

  SecurityMetrics Metrics() const override {
    return {
      .module_name = Name(),
      .counters = {
        {"allowed", allowed_count_},
        {"throttled", throttled_count_},
      },
      .gauges = {
        {"tracked_ips", static_cast<double>(buckets_.size())},
      }
    };
  }

  void ResetMetrics() override {
    std::lock_guard lock(mutex_);
    allowed_count_ = 0;
    throttled_count_ = 0;
    buckets_.clear();
  }

  std::string Name() const override { return "RateLimiter"; }

private:
  struct TokenBucket {
    double tokens = -1;  // -1 signals uninitialised
    std::chrono::steady_clock::time_point last_refill;
  };

  Config config_;
  std::unordered_map<std::string, TokenBucket> buckets_;
  mutable std::mutex mutex_;
  std::atomic<u64> allowed_count_{0};
  std::atomic<u64> throttled_count_{0};
};
} // namespace tsc::sec::mod

#endif