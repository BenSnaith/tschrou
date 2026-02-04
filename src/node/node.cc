#include "node/node.h"

#include "fingertable.h"
#include "net/tcp_client.h"

#include <iostream>

namespace tsc::node {
using namespace tsc::tcp;
using namespace tsc::hsh;

Node::Node(const Config& config)
    : config_(config), address_{.ip_ = config.ip_, .port_ = config.port_} {
  id_ = Hash::HashNode(address_);
  finger_table_ = std::make_unique<FingerTable>(id_);
  server_ = std::make_unique<TcpServer>(config_.port_, this);
}

Node::~Node() {
  Shutdown();
}

bool Node::Create() {
  {
    std::lock_guard lock(ring_mutex_);
    predecessor_ = std::nullopt;
    successor_ = Info();
  }

  finger_table_->InitialiseTo(Info());

  if(!server_->Start()) {
    return false;
  }

  running_ = true;
  stabilise_thread_ = std::jthread(&Node::StabilisationLoop, this);
  fix_fingers_thread_ = std::jthread(&Node::FixFingersLoop, this);
  check_predecessor_thread_ = std::jthread(&Node::CheckPredecessorLoop, this);

  return true;
}

bool Node::Join(const NodeAddress& known_node) {
  if(!server_->Start()) {
    return false;
  }

  auto successor = TcpClient::FindSuccessor(known_node, id_);
  if(!successor) {
    server_->Stop();
    return false;
  }

  {
    std::lock_guard lock(ring_mutex_);
    predecessor_ = std::nullopt;
    successor_ = successor;
  }

  finger_table_->InitialiseTo(*successor);

  running_ = true;
  stabilise_thread_ = std::jthread(&Node::StabilisationLoop, this);
  fix_fingers_thread_ = std::jthread(&Node::FixFingersLoop, this);
  check_predecessor_thread_ = std::jthread(&Node::CheckPredecessorLoop, this);

  std::cout << "Joined Ring: " << successor_->address_.ToString() << std::end;
  return true;
}

void Node::Leave() {  }

void Node::Shutdown() {}

std::optional<NodeInfo> Node::FindSuccessor(NodeID node_id) {  }

std::optional<NodeInfo> Node::ClosestPredecingNode(NodeID id) {  }

void Node::Notify(const NodeInfo& node) {

}

std::optional<NodeInfo> Node::GetPredecessor() const {  }

std::optional<NodeInfo> Node::GetSuccessor() const {  }

bool Node::Put(const std::string& key, const std::string& value) {  }

std::optional<std::string> Node::Get(const std::string& key) {  }

bool Node::Remove(const std::string& key) {  }

void Node::LocalPut(const std::string& key, const std::string& value) {  }

std::optional<std::string> Node::LocalGet(const std::string& key) const {  }

std::vector<std::pair<std::string, std::string>> Node::GetKeysInRange(
    NodeID start, NodeID end) {

}

void Node::Stabilise() {  }


void Node::FixFingers() {  }


void Node::CheckPredecessor() {  }

bool Node::IsAlive(const NodeAddress& address) {  }

void Node::StabilisationLoop() {  }

void Node::FixFingersLoop() {  }

void Node::CheckPredecessorLoop() {  }

}  // namespace tsc::node