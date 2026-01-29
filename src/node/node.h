#ifndef NODE_H
#define NODE_H

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#include "types/types.h"
#include "net/tcp_server.h"

using namespace tsc::type;

namespace tsc::node {
class Node {
 public:
  struct Config {
    std::string ip_{"127.0.0.1"};
    u16 port_{8000};

    constexpr std::chrono::milliseconds stabilise_interval{1000};
    constexpr std::chrono::milliseconds fix_fingers_interval{500};
    constexpr std::chrono::milliseconds check_predecessor_interval{2000};

    constexpr int successor_list_size{3};
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

  bool put(const std::string& key, const std::string& value);

  [[nodiscard]] std::optional<std::string> Get(const std::string& key);

  bool remove(const std::string& key);

  // local operations (YOU ARE THE NODE)

  void LocalPut(const std::string& key, const std::string& value);

  [[nodiscard]] std::optional<std::string> LocalGet(
      const std::string& key) const;

  std::vector<std::pair<std::string, std::string>> GetKeysInRange(NodeID start,
                                                                  NodeID end);

  // getters

  [[nodiscard]] NodeID ID() const { return id_; }
  [[nodiscard]] NodeAddress Address() const { return address_; }
  [[nodiscard]] NodeInfo Info() const {
    return {.id_ = id_, .address_ = address_};
  }

 private:
  // heartbeat

  void Stabilise();

  void FixFingers();

  void CheckPredecessor();

  void StabilisationLoop();
  void FixFingersLoop();
  void CheckPredecessorLoop();

  // helpers

  std::optional<NodeInfo> ClosestPredecingNode(NodeID id);

  bool IsAlive(const NodeAddress& address);

  void TransferKeysTo(const NodeInfo& target);

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
};
}  // namespace tsc::node

#endif NODE_H