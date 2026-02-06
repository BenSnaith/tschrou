#include "net/tcp_server.h"
#include "node/node.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstring>
#include <format>
#include <iostream>

#include "protocol/message.h"

namespace tsc::tcp {
using namespace tsc::msg;
using namespace tsc::node;

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
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ip_str, sizeof(ip_str));
        u16 client_port = ntohs(client_addr.sin_port);

        NodeAddress sender_addr {
          .ip_ = std::string(ip_str),
          .port_ = client_port,
        };
        HandleClient(client_socket, sender_addr);
      }
    }
  }
}

void TcpServer::HandleClient(int client_socket, const NodeAddress& sender) {
  timeval tv{};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::vector<std::byte> buffer(4096);
  ssize_t received = recv(client_socket, buffer.data(), buffer.size(), 0);

  if (received > 0) {
    buffer.resize(received);

    auto msg_type = GetMessageType(buffer);
    if (msg_type) {
      auto& policy = node_->GetSecurityPolicy();
      if (!policy.AllowMessage(sender, *msg_type)) {
        close(client_socket);
        return;
      }
    }

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

  MessageType type = *GetMessageType(message);

  try {
    switch (type) {
      case MessageType::kFindSuccessorRequest: {
        auto req = FindSuccessorRequest::Deserialise(message);
        auto successor = node_->FindSuccessor(req.id_);

        FindSuccessorResponse response;
        if(successor) {
          response.found_ = true;
          response.successor_ = *successor;
        }
        else {
          response.found_ = false;
        }
        return response.Serialise();
      }
      case MessageType::kGetPredecessorRequest: {
        auto predecessor = node_->GetPredecessor();

        GetPredecessorResponse response;
        if(predecessor) {
          response.has_predecessor_ = true;
          response.predecessor_ = *predecessor;
        }
        else {
          response.has_predecessor_ = false;
        }
        return response.Serialise();
      }
      case MessageType::kNotify: {
        auto msg = NotifyMessage::Deserialise(message);
        node_->Notify(msg.node_);

        NotifyAck ack;
        ack.accepted_ = true;
        return ack.Serialise();
      }
      case MessageType::kPing: {
        return PongMessage().Serialise();
      }
      case MessageType::kGetRequest: {
        auto req = GetRequest::Deserialise(message);
        auto value = node_->LocalGet(req.key_);

        GetResponse response;
        if(value) {
          response.found_ = true;
          response.value_ = *value;
        }
        else {
          response.found_ = false;
        }
        return response.Serialise();
      }
      case MessageType::kPutRequest: {
        auto req = PutRequest::Deserialise(message);
        node_->LocalPut(req.key_, req.value_);

        PutResponse response;
        response.success_ = true;
        return response.Serialise();
      }
      case MessageType::kTransferKeysRequest: {
        auto req = TransferKeysRequest::Deserialise(message);
        auto keys = node_->GetKeysInRange(req.start_, req.end_);

        TransferKeysResponse response;
        response.keys_ = keys;
        return response.Serialise();
      }
      default: {
        return ErrorResponse("Unknown message type").Serialise();
      }
    }
  }
  catch (const std::exception& e) {
    return ErrorResponse{std::format("{}", e.what())}.Serialise();
  }

  return {};
}

}  // namespace tsc::tcp