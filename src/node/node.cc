#include "node/node.h"

namespace tsc::node {
using namespace tsc::tcp;

Node::Node(const Config& config)
    : config_(config), address_{.ip_ = config.ip_, .port_ = config.port_} {
  id_ = Hash::HashNode(address_);
  finger_table_ = std::make_unique<FingerTable>(id_);
  server_ = std::make_unique<TcpServer>(config_.port_, this);
}
}  // namespace tsc::node