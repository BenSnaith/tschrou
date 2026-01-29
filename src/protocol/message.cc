#include "protocol/message.h"

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

void WriteU16(std::vector<std::byte>& buff, u16 value) {
  buff.push_back(
      static_cast<std::vector<std::byte>::value_type>(value >> 8 & 0xFF));
  buff.push_back(
    static_cast<std::vector<std::byte>::value_type>(value & 0xFF));
}

u16 ReadU16(const u8* data) {
  return static_cast<u16>(data[0]) << 8 | static_cast<u16>(data[1]);
}

void WriteString(std::vector<std::byte>& data, std::string value) {
  WriteU32(data, static_cast<u32>(value.length()));
  data.insert(data.end(), value.begin(), value.end());
}

std::string ReadString(const u8* data) {
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

std::vector<std::byte> FindSuccessorResponse::Serialise() const {  }

FindSuccessorResponse FindSuccessorResponse::Deserialise(
    std::span<std::byte> data) {

}

// -------------------------------------------
// GetPredecessorRequest
// -------------------------------------------

std::vector<std::byte> GetPredecessorRequest::Serialise() const {  }

GetPredecessorRequest GetPredecessorRequest::Deserialise(
    std::span<std::byte> data) {

}

// -------------------------------------------
// GetPredecessorResponse
// -------------------------------------------

std::vector<std::byte> GetPredecessorResponse::Serialise() const {  }

GetPredecessorResponse GetPredecessorResponse::Deserialise(
    std::span<std::byte> data) {

}

// -------------------------------------------
// NotifyMessage
// -------------------------------------------

std::vector<std::byte> NotifyMessage::Serialise() const {  }

NotifyMessage NotifyMessage::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// NotifyAck
// -------------------------------------------

std::vector<std::byte> NotifyAck::Serialise() const {  }

NotifyAck NotifyAck::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// PingMessage
// -------------------------------------------

std::vector<std::byte> PingMessage::Serialise() const {  }

PingMessage PingMessage::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// PongMessage
// -------------------------------------------

std::vector<std::byte> PongMessage::Serialise() const {  }

PongMessage PongMessage::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// GetRequest
// -------------------------------------------

std::vector<std::byte> GetRequest::Serialise() const {  }

GetRequest GetRequest::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// GetResponse
// -------------------------------------------

std::vector<std::byte> GetResponse::Serialise() const {  }

GetResponse GetResponse::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// PutRequest
// -------------------------------------------

std::vector<std::byte> PutRequest::Serialise() const {  }

PutRequest PutRequest::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// PutResponse
// -------------------------------------------

std::vector<std::byte> PutResponse::Serialise() const {  }

PutResponse PutResponse::Deserialise(std::span<std::byte> data) {  }

// -------------------------------------------
// TransferKeysRequest
// -------------------------------------------

std::vector<std::byte> TransferKeysRequest::Serialise() const {  }

TransferKeysRequest TransferKeysRequest::Deserialise(
    std::span<std::byte> data) {

}

// -------------------------------------------
// TransferKeysResponse
// -------------------------------------------

std::vector<std::byte> TransferKeysResponse::Serialise() const {  }

TransferKeysResponse TransferKeysResponse::Deserialise(
    std::span<std::byte> data) {

}

// -------------------------------------------
// ErrorResponse
// -------------------------------------------

std::vector<std::byte> ErrorResponse::Serialise() const {  }

ErrorResponse ErrorResponse::Deserialise(std::span<std::byte> data) {  }

Result<MessageType> GetMessageType(std::span<std::byte> data) {
  if(data.empty()) {
    return std::unexpected("Empty message");
  }
  return static_cast<MessageType>(data[0]);
}

} // namespace tsc::msg