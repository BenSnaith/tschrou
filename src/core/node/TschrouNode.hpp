#ifndef TSCHROU_CORE_NODE
#define TSCHROU_CORE_NODE

#include <memory>

namespace tschrou::core {
class TschrouNode {

private:
  std::unique_ptr<TschrouNode> successor; // next
  std::unique_ptr<TschrouNode> predecessor; // prev
};
} // namespace tschrou::core

#endif