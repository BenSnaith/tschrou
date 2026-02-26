#ifndef SECURITY_MODULE_H
#define SECURITY_MODULE_H

#include <memory>
#include <string>
#include <vector>
#include <print>

#include "types/types.h"
#include "protocol/message.h"

namespace tsc::sec {
using namespace tsc::type;
using namespace tsc::msg;

struct SecurityMetrics {
  std::string module_name;
  std::vector<std::pair<std::string, u64>> counters;
  std::vector<std::pair<std::string, double>> gauges;
};

// virtual class for security methods to inherit
class ISecurityModule {
public:
  virtual ~ISecurityModule() = default;

  virtual bool AllowNode(const NodeInfo& node) {
    std::print("calling ISecurityModule::AllowNode, it should be virtual");
    return true;
  }

  virtual bool AllowMessage(const NodeAddress& sender, MessageType type) {
    std::print("calling ISecurityModule::AllowMessage, it should be virtual");
    return true;
  }

  virtual bool ValidateLookup(NodeID target, const NodeInfo& result) {
    std::print("calling ISecurityModule::ValidateLookup, it should be virtual");
    return true;
  }

  virtual void Tick() {}

  virtual SecurityMetrics Metrics() const {
    return {.module_name = Name(), .counters = {}, .gauges = {}};
  }

  virtual void ResetMetrics() = 0;

  virtual std::string Name() const = 0;
};

// security policy contains many implementations of ISecurityPolicy
class SecurityPolicy {
public:
  void AddModule(std::shared_ptr<ISecurityModule> module) {
    modules_.push_back(std::move(module));
  }

  bool AllowNode(const NodeInfo& node) const {
    for (const auto& m : modules_) {
      if (!m->AllowNode(node)) {
        return false;
      }
    }
    return true;
  }

  bool AllowMessage(const NodeAddress& sender, MessageType type) const {
    for (const auto& m : modules_) {
      if (!m->AllowMessage(sender, type)) {
        return false;
      }
    }
    return true;
  }

  bool ValidateLookup(NodeID target, const NodeInfo& result) const {
    for (const auto& m : modules_) {
      if (!m->ValidateLookup(target, result)) {
        return false;
      }
    }
    return true;
  }

  void Tick() {
    for (auto& m : modules_) {
      m->Tick();
    }
  }

  std::vector<SecurityMetrics> GetAllMetrics() const {
    std::vector<SecurityMetrics> all;
    all.reserve(modules_.size());
    for (const auto& m : modules_) {
      all.push_back(m->Metrics());
    }
    return all;
  }

  void ResetAllMetrics() {
    for (auto& m : modules_) {
      m->ResetMetrics();
    }
  }

  bool Empty() const { return modules_.empty(); }

  // trying to avoid libraries.
  std::string MetricsToJSON() const;

private:
  std::vector<std::shared_ptr<ISecurityModule>> modules_;
};
} // namespace tsc::sec

#endif
