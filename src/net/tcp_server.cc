#include "net/tcp_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstring>
#include <iostream>

namespace tsc::tcp {
TcpServer::TcpServer(u16 port, Node* node) : port_(port), node_(node) {}

TcpServer::~TcpServer() { Stop(); }

bool TcpServer::Start() {
  server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket_ < 0) {
    std::cerr << "Failed to create socket" << '\n';
    return false;
  }

  int opt = 1;
  setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port_);

  if (bind(server_socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) <
      0) {
    std::cerr << "Failed to bind to port " << port_ << '\n';
    close(server_socket_);
    return false;
  }

  if (listen(server_socket_, 10) < 0) {
    std::cerr << "Failed to listen on port " << port_ << '\n';
    close(server_socket_);
    return false;
  }

  int flags = fcntl(server_socket_, F_GETFL, 0);
  fcntl(server_socket_, F_SETFL, flags | O_NONBLOCK);

  running_ = true;
  server_thread_ = std::jthread(&TcpServer::ServerLoop, this);

  return true;
}

void TcpServer::Stop() {
  running_ = false;

  if (server_socket_ >= 0) {
    close(server_socket_);
    server_socket_ = -1;
  }

  if (server_thread_.joinable()) {
    server_thread_.join();
  }
}

void TcpServer::ServerLoop() {
  while (running_) {
    pollfd pfd{};
    pfd.fd = server_socket_;
    pfd.events = POLLIN;

    int result = poll(&pfd, 1, 100);

    if (result > 0 && (pfd.revents & POLLIN)) {
      sockaddr_in client_addr{};
      socklen_t addr_len = sizeof(client_addr);

      int client_socket = accept(
          server_socket_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

      if (client_socket >= 0) {
        HandleClient(client_socket);
      }
    }
  }
}

void TcpServer::HandleClient(int client_socket) {
  timeval tv{};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::vector<std::byte> buffer(4096);
  ssize_t received = recv(client_socket, buffer.data(), buffer.size(), 0);

  if (received > 0) {
    buffer.resize(received);

    auto response = ProcessMessage(buffer);

    if (!response.empty()) {
      send(client_socket, response.data(), response.size(), 0);
    }
  }

  close(client_socket);
}

std::vector<std::byte> TcpServer::ProcessMessage(std::span<std::byte> message) {
  if (message.empty()) {
    return {};
  }

  MessageType type = GetMessageType(message);

  try {
    switch (type) {
      case MessageType::FIND_SUCCESSOR_REQUEST: {

      }

      case
    }
  }

  return {};
}

}  // namespace tsc::tcp