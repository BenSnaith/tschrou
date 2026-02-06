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

  std::cout << "Joined Ring: " << successor_->address_.ToString() << "\n";
  return true;
}

void Node::Leave() {
  std::lock_guard lock(ring_mutex_);
  if (successor_ && successor_->id_ != id_) {
    auto keys = storage_.Keys();
    for (const auto& key : keys) {
      auto value = storage_.Get(key);
      if (value) {
        TcpClient::Put(successor_->address_, key, *value);
      }
    }
  }

  Shutdown();
}

void Node::Shutdown() {
  running_ = false;

  if (stabilise_thread_.joinable()) { stabilise_thread_.join(); }
  if (fix_fingers_thread_.joinable()) { fix_fingers_thread_.join(); }
  if (check_predecessor_thread_.joinable()) { check_predecessor_thread_.join(); }

  server_->Stop();
}

std::optional<NodeInfo> Node::FindSuccessor(NodeID node_id) {
  NodeAddress target;
  {
    std::lock_guard lock(ring_mutex_);

    if (!successor_) {
      return std::nullopt;
    }

    if (InRangeExclusiveInclusive(node_id, id_, successor_->id_)) {
      return successor_;
    }

    auto closest = ClosestPrecedingNode(node_id);

    if (!closest || closest->id_ == id_) {
      return successor_;
    }

    target = closest->address_;
  }

  return TcpClient::FindSuccessor(target, node_id);
}

std::optional<NodeInfo> Node::ClosestPrecedingNode(NodeID node_id) {
  if (auto finger_result = finger_table_->ClosestPrecedingNode(node_id)) {
    return finger_result;
  }

  if (successor_ && InRangeExclusive(successor_->id_, id_, node_id)) {
    return successor_;
  }

  return std::nullopt;
}

void Node::Notify(const NodeInfo& node) {
  std::lock_guard lock(ring_mutex_);

  if (!predecessor_ || InRangeExclusive(node.id_, predecessor_->id_, id_)) {
    std::cout << "Update predecessor to " << node.id_ << " at " << node.address_.ToString() << "\n";
    predecessor_ = node;
  }
}

std::optional<NodeInfo> Node::GetPredecessor() const {
  std::lock_guard lock(ring_mutex_);
  return predecessor_;
}

std::optional<NodeInfo> Node::GetSuccessor() const {
  std::lock_guard lock(ring_mutex_);
  return successor_;
}

bool Node::Put(const std::string& key, const std::string& value) {
  KeyID key_id = hsh::Hash::HashKey(key);

  auto successor = FindSuccessor(key_id);
  if (!successor) {
    return false;
  }

  // we are the responsible node for this key, store locally
  if (successor->id_ == id_) {
    LocalPut(key, value);
    return true;
  }

  return TcpClient::Put(successor->address_, key, value);
}

std::optional<std::string> Node::Get(const std::string& key) {
  KeyID key_id = hsh::Hash::HashKey(key);

  auto successor = FindSuccessor(key_id);
  if (!successor) {
    return std::nullopt;
  }

  // we are the responsible node for this key, store locally
  if (successor->id_ == id_) {
    return LocalGet(key);
  }

  return TcpClient::Get(successor->address_, key);
}

bool Node::Remove(const std::string& key) {
  return storage_.Remove(key);
}

void Node::LocalPut(const std::string& key, const std::string& value) {
  storage_.Put(key, value);
}

std::optional<std::string> Node::LocalGet(const std::string& key) const {
  return storage_.Get(key);
}

std::vector<std::pair<std::string, std::string>> Node::GetKeysInRange(
    NodeID start, NodeID end) {
  return storage_.GetRange(start, end);
}

void Node::Stabilise() {
  std::optional<NodeInfo> successor_copy;
  {
    std::lock_guard lock(ring_mutex_);
    successor_copy = successor_;
  }

  if (!successor_copy) {
    return;
  }

  auto predecessor = TcpClient::GetPredecessor(successor_copy->address_);

  if (predecessor) {
    std::lock_guard lock(ring_mutex_);

    if (InRangeExclusive(predecessor->id_, id_, successor_->id_)) {
      std::cout << "Stabilise: updating successor from " << successor_->id_
        << " to " << predecessor->id_ << "\n";
      successor_ = predecessor;
      finger_table_->Set(0, *predecessor);
    }
  }

  {
    std::lock_guard lock(ring_mutex_);
    successor_copy = successor_;
  }

  if (successor_copy && successor_copy->id_ != id_) {
    TcpClient::Notify(successor_copy->address_, Info());
  }
}


void Node::FixFingers() {
  next_finger_ = (next_finger_ + 1) % FingerTable::kSize;

  NodeID finger_id = finger_table_->GetStart(next_finger_);
  auto successor = FindSuccessor(finger_id);

  if (successor) {
    finger_table_->Set(next_finger_, *successor);
  }
}


void Node::CheckPredecessor() {
  std::lock_guard lock(ring_mutex_);

  if (predecessor_) {
    if (!IsAlive(predecessor_->address_)) {
      std::cout << "Predecessor " << predecessor_->id_ << " has failed" << "\n";
      predecessor_ = std::nullopt;
    }
  }
}

bool Node::IsAlive(const NodeAddress& address) {
  return TcpClient::Ping(address);
}

void Node::StabilisationLoop() {
  while (running_) {
    std::this_thread::sleep_for(
      std::chrono::milliseconds(Config::stabilise_interval)
    );

    if (running_) {
      Stabilise();
    }
  }
}

void Node::FixFingersLoop() {
  while (running_) {
    std::this_thread::sleep_for(
      std::chrono::milliseconds(Config::fix_fingers_interval)
    );

    if (running_) {
      FixFingers();
    }
  }
}

void Node::CheckPredecessorLoop() {
  while (running_) {
    std::this_thread::sleep_for(
      std::chrono::milliseconds(Config::check_predecessor_interval)
    );

    if (running_) {
      CheckPredecessor();
    }
  }
}

void Node::PrintState() const {
  std::lock_guard lock(ring_mutex_);

  std::cout << "\n" << " === Node State === " << "\n";
  std::cout << "ID: " << id_ << "\n";
  std::cout << "Address: " << address_.ToString() << "\n";

  if (predecessor_) {
    std::cout << "Predecessor: " << predecessor_->id_
      << " at " << predecessor_->address_.ToString() << "\n";
  }
  else {
    std::cout << "Predecessor: (none)" << "\n";
  }

  if (successor_) {
    std::cout << "Successor: " << successor_->id_
      << " at " << successor_->address_.ToString() << "\n";
  }
  else {
    std::cout << "Successor: (none)" << "\n";
  }

  std::cout << "Stored Keys: " << storage_.Size() << "\n";
  std::cout << "==================================" << "\n" << "\n";
}

void Node::PrintFingerTable() const {
  finger_table_->Print();
}

}  // namespace tsc::node