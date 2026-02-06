#include "net/tcp_client.h"
#include "types/types.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <iostream>

#include "protocol/message.h"

namespace tsc::tcp {
using namespace tsc::msg;
using namespace tsc::type;
int TcpClient::ConnectTo(const NodeAddress& target,
                         [[maybe_unused]] std::chrono::milliseconds timeout) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if(sock < 0) {
    return -1;
  }

  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(target.port_);

  if(inet_pton(AF_INET, target.ip_.c_str(), &addr.sin_addr) <= 0) {
    close(sock);
    return -1;
  }

  int result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

  if(result < 0) {
    if(errno == EINPROGRESS) {
    }
    else {
      close(sock);
      return -1;
    }
  }

  fcntl(sock, F_SETFL, flags);

  return sock;
}

bool TcpClient::SendAll(int socket, const std::vector<std::byte>& data) {
  size_t total_sent = 0;
  while(total_sent < data.size()) {
    ssize_t sent = send(socket, data.data() + total_sent,
      data.size() - total_sent, 0);
    if(sent <= 0) {
      return false;
    }
    total_sent += sent;
  }
  return true;
}

std::optional<std::vector<std::byte>> TcpClient::ReceiveMessage(
    int socket, std::chrono::milliseconds timeout) {
  timeval tv{};
  tv.tv_sec = timeout.count() / 1000;
  tv.tv_usec = (timeout.count() % 1000) * 1000;
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  std::vector<std::byte> buffer(4096);
  ssize_t received = recv(socket, buffer.data(), buffer.size(), 0);

  if(received < 0) {
    return std::nullopt;
  }

  buffer.resize(received);
  return buffer;
}

std::optional<std::vector<std::byte>> TcpClient::SendRequest(
    const NodeAddress& target, const std::vector<std::byte>& request,
    std::chrono::milliseconds timeout) {
  int sock = ConnectTo(target, timeout);
  if(sock < 0) {
    return std::nullopt;
  }

  if(!SendAll(sock, request)) {
    close(sock);
    return std::nullopt;
  }

  auto response = ReceiveMessage(sock, timeout);

  close(sock);
  return response;
}

std::optional<NodeInfo> TcpClient::FindSuccessor(const NodeAddress& target,
                                                 NodeID id) {
  FindSuccessorRequest request{id};
  auto response = SendRequest(target, request.Serialise());

  if(!response) {
    return std::nullopt;
  }

  try {
    auto resp = FindSuccessorResponse::Deserialise(*response);
    if(resp.found_) {
      return resp.successor_;
    }
  }
  catch(...) {
  }

  return std::nullopt;
}

std::optional<NodeInfo> TcpClient::GetPredecessor(const NodeAddress& target) {
  GetPredecessorRequest request;
  auto response = SendRequest(target, request.Serialise());

  if(!response) {
    return std::nullopt;
  }

  try {
    auto resp = GetPredecessorResponse::Deserialise(*response);
    if(resp.has_predecessor_) {
      return resp.predecessor_;
    }
  }
  catch(...) {

  }

  return std::nullopt;
}

bool TcpClient::Notify(const NodeAddress& target, const NodeInfo& self) {
  NotifyMessage message{self};
  auto response = SendRequest(target, message.Serialise());

  if(!response) {
    return false;
  }

  try {
    auto ack = NotifyAck::Deserialise(*response);
    return ack.accepted_;
  }
  catch(...) {

  }

  return false;
}

bool TcpClient::Ping(const NodeAddress& target) {
  PingMessage message;
  auto response = SendRequest(target, message.Serialise(), std::chrono::milliseconds(2000));

  if(!response) {
    return false;
  }

  try {
    MessageType type = *GetMessageType(*response);
    return type == MessageType::kPong;
  }
  catch(...) {
  }

  return false;
}

std::optional<std::string> TcpClient::Get(const NodeAddress& target,
                                          [[maybe_unused]] const std::string& key) {
  GetRequest request{key};
  auto response = SendRequest(target, request.Serialise());

  if(!response) {
    return std::nullopt;
  }

  try {
    auto resp = GetResponse::Deserialise(*response);
    if(resp.found_) {
      return resp.value_;
    }
  }
  catch(...) {}

  return std::nullopt;
}

bool TcpClient::Put(const NodeAddress& target, [[maybe_unused]] const std::string& key,
                    [[maybe_unused]] const std::string& value) {
  PutRequest request{key, value};
  auto response = SendRequest(target, request.Serialise());

  if(!response) {
    return false;
  }

  try {
    auto resp = PutResponse::Deserialise(*response);
    return resp.success_;
  }
  catch(...) {}

  return false;
}

std::optional<std::vector<std::pair<std::string, std::string>>>
TcpClient::TransferKeys(const NodeAddress& target, NodeID start, NodeID end) {
  TransferKeysRequest request;
  request.start_ = start;
  request.end_ = end;

  auto response = SendRequest(target, request.Serialise());

  if(!response) {
    return std::nullopt;
  }

  try {
    auto resp = TransferKeysResponse::Deserialise(*response);
    return resp.keys_;
  }
  catch(...) {}

  return std::nullopt;
}
} // namespace tsc::tcp

