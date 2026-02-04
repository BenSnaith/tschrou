#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <string>
#include <optional>
#include <chrono>
#include <optional>

#include "types/types.h"

namespace tsc::tcp {
using namespace tsc::type;
class TcpClient {
public:
  static constexpr auto kDefaultTimeout = std::chrono::milliseconds(5000);

  static std::optional<std::vector<std::byte>> SendRequest(
    const NodeAddress& target,
    const std::vector<std::byte>& request,
    std::chrono::milliseconds timeout = kDefaultTimeout
  );

  static std::optional<NodeInfo> FindSuccessor(
    const NodeAddress& target,
    NodeID id
  );

  static std::optional<NodeInfo> GetPredecessor(const NodeAddress& target);

  static bool Notify(const NodeAddress& target, const NodeInfo& self);

  static bool Ping(const NodeAddress& target);

  static std::optional<std::string> Get(
    const NodeAddress& target,
    const std::string& key
  );

  static bool Put(
    const NodeAddress& target,
    const std::string& key,
    const std::string& value
  );

  static std::optional<std::vector<std::pair<std::string, std::string>>>
  TransferKeys(
    const NodeAddress& target,
    NodeID start,
    NodeID end
  );

private:
  static int ConnectTo(
    const NodeAddress& target,
    std::chrono::milliseconds timeout
  );

  static bool SendAll(int socket, const std::vector<std::byte>& data);

  static std::optional<std::vector<std::byte>> ReceiveMessage(
    int socket, std::chrono::milliseconds timeout
  );
};
} // namespace tsc::tcp

#endif // TCP_CLIENT_H
