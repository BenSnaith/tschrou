#ifndef NODE_H
#define NODE_H

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#include "types/types.h"
#include "net/tcp_server.h"
#include "net/tcp_client.h"
#include "node/fingertable.h"
#include "node/storage.h"
#include "security/security_module.h"
#include "util/hash.h"

namespace tsc::node {
using namespace tsc::type;
using namespace tsc::tcp;
using namespace tsc::sec;
class Node {
 public:
  struct Config {
    std::string ip_{"127.0.0.1"};
    u16 port_{8000};

    static constexpr std::chrono::milliseconds stabilise_interval{1000};
    static constexpr std::chrono::milliseconds fix_fingers_interval{500};
    static constexpr std::chrono::milliseconds check_predecessor_interval{2000};

    static constexpr int successor_list_size{3};

    // security flags
    bool enable_id_verification{false};
    bool enable_subnet_diversity{false};
    bool enable_rate_limiting{false};
    bool enable_lookup_validation{false};
    bool enable_peer_age{false};
    bool enable_honeypot{false};

    int subnet_max_per{2};
    int rate_limit_max_tokes{2};
    double rate_limit_refill{10.0};
    int lookup_validation_checks{1};
    double peer_age_min_seconds{30.0};
    int honeypot_count{10};
  };

  explicit Node(const Config& config);
  ~Node();

  // life-cycle

  bool Create();

  bool Join(const NodeAddress& known_node);

  void Leave();

  void Shutdown();

  // core operations

  std::optional<NodeInfo> FindSuccessor(NodeID node_id);

  void Notify(const NodeInfo& node);

  [[nodiscard]] std::optional<NodeInfo> GetPredecessor() const;

  [[nodiscard]] std::optional<NodeInfo> GetSuccessor() const;

  // classic hash table operations

  bool Put(const std::string& key, const std::string& value);

  [[nodiscard]] std::optional<std::string> Get(const std::string& key);

  bool Remove(const std::string& key);

  // local operations (YOU ARE THE NODE)

  void LocalPut(const std::string& key, const std::string& value);

  [[nodiscard]] std::optional<std::string> LocalGet(
      const std::string& key) const;

  std::vector<std::pair<std::string, std::string>> GetKeysInRange(NodeID start,
                                                                  NodeID end);

  // security

  SecurityPolicy& GetSecurityPolicy() { return security_policy_; }
  const SecurityPolicy& GetSecurityPolicy() const { return security_policy_; };

  void DumpMetrics() const;

  std::vector<NodeInfo> AlternativeNodes() const;

  // getters

  [[nodiscard]] NodeID ID() const { return id_; }
  [[nodiscard]] NodeAddress Address() const { return address_; }
  [[nodiscard]] NodeInfo Info() const {
    return {.id_ = id_, .address_ = address_};
  }

  void PrintState() const;
  void PrintFingerTable() const;

 private:
  void InitialiseSecurity();

  // heartbeat

  void Stabilise();

  void FixFingers();

  void CheckPredecessor();

  void StabilisationLoop();
  void FixFingersLoop();
  void CheckPredecessorLoop();

  // helpers

  std::optional<NodeInfo> ClosestPrecedingNode(NodeID id);

  bool IsAlive(const NodeAddress& address);

  // state

  Config config_;
  NodeID id_;
  NodeAddress address_;

  std::optional<NodeInfo> predecessor_;
  std::optional<NodeInfo> successor_;
  std::vector<NodeInfo> successor_list_;
  mutable std::mutex ring_mutex_;

  std::unique_ptr<FingerTable> finger_table_;
  Storage storage_;

  std::unique_ptr<TcpServer> server_;

  std::atomic<bool> running_{false};
  std::jthread stabilise_thread_;
  std::jthread fix_fingers_thread_;
  std::jthread check_predecessor_thread_;

  int next_finger_{0};

  SecurityPolicy security_policy_;
  std::shared_ptr<class HoneypotMonitor> honeypot_monitor_;
};
}  // namespace tsc::node

#endif