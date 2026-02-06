#include "protocol/message.h"

#include <algorithm>

namespace tsc::msg {
namespace {
void WriteU32(std::vector<std::byte>& buff, u32 value) {
  buff.push_back(
      static_cast<std::vector<std::byte>::value_type>(value >> 24 & 0xFF));
  buff.push_back(
      static_cast<std::vector<std::byte>::value_type>(value >> 16 & 0xFF));
  buff.push_back(
      static_cast<std::vector<std::byte>::value_type>(value >> 8 & 0xFF));
  buff.push_back(
      static_cast<std::vector<std::byte>::value_type>(value & 0xFF));
}

u32 ReadU32(const u8* data) {
  return (static_cast<u32>(data[0]) << 24) |
         (static_cast<u32>(data[1]) << 16) |
         (static_cast<u32>(data[2]) << 8) |
         (static_cast<u32>(data[3]) << 0);
}

u32 ReadU32(const std::byte* data) {
  return (static_cast<u32>(std::to_integer<u8>(data[0])) << 24) |
         (static_cast<u32>(std::to_integer<u8>(data[1])) << 16) |
         (static_cast<u32>(std::to_integer<u8>(data[2])) << 8) |
         (static_cast<u32>(std::to_integer<u8>(data[3])) << 0);
}

void WriteU16(std::vector<std::byte>& buff, u16 value) {
  buff.push_back(
      static_cast<std::vector<std::byte>::value_type>(value >> 8 & 0xFF));
  buff.push_back(
    static_cast<std::vector<std::byte>::value_type>(value & 0xFF));
}

u16 ReadU16(const u8* data) {
  return static_cast<u16>(data[0]) << 8 | static_cast<u16>(data[1]);
}

u16 ReadU16(const std::byte* data) {
  return static_cast<u16>(std::to_integer<u8>(data[0])) << 8
    | static_cast<u16>(std::to_integer<u8>(data[1]));
}

void WriteString(std::vector<std::byte>& data, std::string value) {
  WriteU32(data, static_cast<u32>(value.length()));
  std::ranges::transform(value,
               std::back_inserter(data),
               [](char c) { return static_cast<std::byte>(c); });
}

std::string ReadString(const u8* data) {
  u32 len = ReadU32(data);
  data += 4;
  std::string result{reinterpret_cast<const char*>(data), len};
  data += len;
  return result;
}

std::string ReadString(std::byte*& data) {
  u32 len = ReadU32(data);
  data += 4;
  std::string result{reinterpret_cast<const char*>(data), len};
  data += len;
  return result;
}

void WriteNodeInfo(std::vector<std::byte>& buff, const NodeInfo& node) {
  WriteU32(buff, node.id_);
  WriteString(buff, node.address_.ip_);
  WriteU16(buff, node.address_.port_);
}

NodeInfo ReadNodeInfo(const u8* data) {
  NodeInfo node;
  node.id_ = ReadU32(data);
  data += 4;
  node.address_.ip_ = ReadString(data);
  node.address_.port_ = ReadU16(data);
  data += 2;
  return node;
}

NodeInfo ReadNodeInfo(std::byte*& data) {
  NodeInfo node;
  node.id_ = ReadU32(data);
  data += 4;
  node.address_.ip_ = ReadString(data);
  node.address_.port_ = ReadU16(data);
  data += 2;
  return node;
}
} // namespace

// -------------------------------------------
// FindSuccessorRequest
// -------------------------------------------

std::vector<std::byte> FindSuccessorRequest::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteU32(buffer, id_);
  return buffer;
}

FindSuccessorRequest FindSuccessorRequest::Deserialise(
    std::span<std::byte> data) {
  FindSuccessorRequest request;
  request.id_ = ReadU32(reinterpret_cast<const u8*>(data.data() + 1));
  return request;
}

// -------------------------------------------
// FindSuccessorResponse
// -------------------------------------------

std::vector<std::byte> FindSuccessorResponse::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  buffer.push_back(found_ ? std::byte{1} : std::byte{0});
  if(found_) {
    WriteNodeInfo(buffer, successor_);
  }
  return buffer;
}

FindSuccessorResponse FindSuccessorResponse::Deserialise(
    std::span<std::byte> data) {
  FindSuccessorResponse response;
  std::byte* ptr = data.data() + 1;
  response.found_ = ptr++ != nullptr;
  if(response.found_) {
    response.successor_ = ReadNodeInfo(ptr);
  }
  return response;
}

// -------------------------------------------
// GetPredecessorRequest
// -------------------------------------------

std::vector<std::byte> GetPredecessorRequest::Serialise() const {
  return {static_cast<std::byte>(type_)};
}

GetPredecessorRequest GetPredecessorRequest::Deserialise(
    std::span<std::byte> data) {
  return {};
}

// -------------------------------------------
// GetPredecessorResponse
// -------------------------------------------

std::vector<std::byte> GetPredecessorResponse::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  buffer.push_back(has_predecessor_ ? std::byte{1} : std::byte{0});
  if(has_predecessor_) {
    WriteNodeInfo(buffer, predecessor_);
  }
  return buffer;
}

GetPredecessorResponse GetPredecessorResponse::Deserialise(
    std::span<std::byte> data) {
  GetPredecessorResponse response;
  std::byte* ptr = data.data() + 1;
  response.has_predecessor_ = *ptr++ != std::byte{0};
  if(response.has_predecessor_) {
    response.predecessor_ = ReadNodeInfo(ptr);
  }
  return response;
}

// -------------------------------------------
// NotifyMessage
// -------------------------------------------

std::vector<std::byte> NotifyMessage::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteNodeInfo(buffer, node_);
  return buffer;
}

NotifyMessage NotifyMessage::Deserialise(std::span<std::byte> data) {
  NotifyMessage message;
  std::byte* ptr = data.data() + 1;
  message.node_ = ReadNodeInfo(ptr);
  return message;
}

// -------------------------------------------
// NotifyAck
// -------------------------------------------

std::vector<std::byte> NotifyAck::Serialise() const {
  return {static_cast<std::byte>(type_)};
}

NotifyAck NotifyAck::Deserialise(std::span<std::byte> data) {
  NotifyAck ack;
  ack.accepted_ = data[1] != std::byte{0};
  return ack;
}

// -------------------------------------------
// PingMessage
// -------------------------------------------

std::vector<std::byte> PingMessage::Serialise() const {
  return {static_cast<std::byte>(type_)};
}

PingMessage PingMessage::Deserialise(std::span<std::byte> data) {
  return {};
}

// -------------------------------------------
// PongMessage
// -------------------------------------------

std::vector<std::byte> PongMessage::Serialise() const {
  return {static_cast<std::byte>(type_)};
}

PongMessage PongMessage::Deserialise(std::span<std::byte> data) {
  return {};
}

// -------------------------------------------
// GetRequest
// -------------------------------------------

std::vector<std::byte> GetRequest::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteString(buffer, key_);
  return buffer;
}

GetRequest GetRequest::Deserialise(std::span<std::byte> data) {
  GetRequest request;
  std::byte* ptr = data.data() + 1;
  request.key_ = ReadString(ptr);
  return request;
}

// -------------------------------------------
// GetResponse
// -------------------------------------------

std::vector<std::byte> GetResponse::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  buffer.push_back(found_ ? std::byte{1} : std::byte{0});
  if(found_) {
    WriteString(buffer, value_);
  }
  return buffer;
}

GetResponse GetResponse::Deserialise(std::span<std::byte> data) {
  GetResponse response;
  std::byte* ptr = data.data() + 1;
  response.found_ = *ptr++ != std::byte{0};
  if(response.found_) {
    response.value_ = ReadString(ptr);
  }
  return response;
}

// -------------------------------------------
// PutRequest
// -------------------------------------------

std::vector<std::byte> PutRequest::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteString(buffer, key_);
  WriteString(buffer, value_);
  return buffer;
}

PutRequest PutRequest::Deserialise(std::span<std::byte> data) {
  PutRequest request;
  std::byte* ptr = data.data() + 1;
  request.key_ = ReadString(ptr);
  request.value_ = ReadString(ptr);
  return request;
}

// -------------------------------------------
// PutResponse
// -------------------------------------------

std::vector<std::byte> PutResponse::Serialise() const {
  return {static_cast<std::byte>(type_),
    static_cast<std::byte>(success_ ? 1 : 0)};
}

PutResponse PutResponse::Deserialise(std::span<std::byte> data) {
  PutResponse response;
  response.success_ = (data[1] != std::byte{0});
  return response;
}

// -------------------------------------------
// TransferKeysRequest
// -------------------------------------------

std::vector<std::byte> TransferKeysRequest::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteU32(buffer, start_);
  WriteU32(buffer, end_);
  return buffer;
}

TransferKeysRequest TransferKeysRequest::Deserialise(
    std::span<std::byte> data) {
  TransferKeysRequest request;
  request.start_ = ReadU32(data.data() + 1);
  // this might be an issue...
  request.end_ = ReadU32(data.data() + 5);
  return request;
}

// -------------------------------------------
// TransferKeysResponse
// -------------------------------------------

std::vector<std::byte> TransferKeysResponse::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteU32(buffer, static_cast<u32>(keys_.size()));
  for(const auto& [key, value] : keys_) {
    WriteString(buffer, key);
    WriteString(buffer, value);
  }
  return buffer;
}

TransferKeysResponse TransferKeysResponse::Deserialise(
    std::span<std::byte> data) {
  TransferKeysResponse response;
  std::byte* ptr = data.data() + 1;
  u32 count = ReadU32(ptr);
  ptr += 4;
  for(u32 i{}; i < count; ++i) {
    std::string key = ReadString(ptr);
    std::string value = ReadString(ptr);
    response.keys_.emplace_back(key, value);
  }
  return response;
}

// -------------------------------------------
// ErrorResponse
// -------------------------------------------

std::vector<std::byte> ErrorResponse::Serialise() const {
  std::vector<std::byte> buffer;
  buffer.push_back(static_cast<std::byte>(type_));
  WriteString(buffer, error_message_);
  return buffer;
}

ErrorResponse ErrorResponse::Deserialise(std::span<std::byte> data) {
  ErrorResponse response;
  std::byte* ptr = data.data() + 1;
  response.error_message_ = ReadString(ptr);
  return response;
}

Result<MessageType> GetMessageType(std::span<std::byte> data) {
  if(data.empty()) {
    return std::unexpected("Empty message");
  }
  return static_cast<MessageType>(data[0]);
}

} // namespace tsc::msg