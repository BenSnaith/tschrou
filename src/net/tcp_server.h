#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <span>
#include <thread>
#include <vector>

#include "types/types.h"

// this is gonna cause issues rewriting, refactor.
using namespace tsc::type;

namespace tsc::tcp {
class Node;

class TcpServer {
public:
  explicit TcpServer(u16 port, Node* node);
  ~TcpServer();

  bool Start();

  void Stop();

  bool IsRunning() const;

  u16 Port() const;

private:
  void ServerLoop();

  void HandleClient(int client_socket);

  std::vector<std::byte> ProcessMessage(std::span<std::byte> message);

  u16 port_;
  Node* node_;

  int server_socket_ = -1;
  std::atomic<bool> running_{false};
  std::jthread server_thread_;
};
} // namespace tsc::tcp

#endif TCP_SERVER_H