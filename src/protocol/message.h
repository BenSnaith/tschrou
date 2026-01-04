#ifndef MESSAGE_H
#define MESSAGE_H

#include <span>
#include <vector>

#include "types/types.h"

using namespace tsc::type;

namespace tsc::msg {
enum class MessageType : u8 {
  kFindSuccessorRequest = 0x01,
  kFindSuccessorResponse = 0x02,
  kGetPredecessorRequest = 0x03,
  kGetPredecessorResponse = 0x04,
  kNotify = 0x05,
  kNotifyAck = 0x06,
  kPing = 0x07,
  kPong = 0x08,

  kGetRequest = 0x10,
  kGetResponse = 0x11,
  kPutRequest = 0x12,
  kPutResponse = 0x13,
  kDeleteRequest = 0x14,
  kDeleteResponse = 0x15,

  kTransferKeysRequest = 0x20,
  kTransferKeysResponse = 0x21,

  kErrorResponse = 0xFF,
};

struct Message {
  virtual std::vector<std::byte> Serialise() const = 0;

  virtual ~Message() = default;

  MessageType type_;
};

struct FindSuccessorRequest : Message {
  FindSuccessorRequest() { type_ = MessageType::kFindSuccessorRequest; }
  explicit FindSuccessorRequest(NodeID id) : id_(id) {
    type_ = MessageType::kFindSuccessorRequest;
  }

  std::vector<std::byte> Serialise() const override;
  static FindSuccessorRequest Deserialise(std::span<std::byte> data);

  NodeID id_;
};

struct FindSuccessorResponse : Message {
  FindSuccessorResponse() { type_ = MessageType::kFindSuccessorResponse; }

  std::vector<std::byte> Serialise() const override;
  static FindSuccessorResponse Deserialise(std::span<std::byte> data);

  NodeInfo successor_;
  bool found_;
};

struct GetPredecessorRequest : Message {
  GetPredecessorRequest() { type_ = MessageType::kGetPredecessorRequest; }

  std::vector<std::byte> Serialise() const override;
  static GetPredecessorRequest Deserialise(std::span<std::byte> data);
};

struct GetPredecessorResponse : Message {
  GetPredecessorResponse() { type_ = MessageType::kGetPredecessorResponse; }

  std::vector<std::byte> Serialise() const override;
  static GetPredecessorResponse Deserialise(std::span<std::byte> data);

  NodeInfo predecessor_;
  bool has_predecessor_;
};

struct NotifyMessage : Message {
  NotifyMessage() { type_ = MessageType::kNotify; }
  explicit NotifyMessage(const NodeInfo& node) : node_(node) {
    type_ = MessageType::kNotify;
  }

  std::vector<std::byte> Serialise() const override;
  static NotifyMessage Deserialise(std::span<std::byte> data);

  NodeInfo node_;
};

struct NotifyAck : Message {
  NotifyAck() { type_ = MessageType::kNotifyAck; }

  std::vector<std::byte> Serialise() const override;
  static NotifyAck Deserialise(std::span<std::byte> data);

  bool accepted_;
};

struct PingMessage : Message {
  PingMessage() { type_ = MessageType::kPing; }

  std::vector<std::byte> Serialise() const override;
  static PingMessage Deserialise(std::span<std::byte> data);
};

struct PongMessage : Message {
  PongMessage() { type_ = MessageType::kPong; }

  std::vector<std::byte> Serialise() const override;
  static PongMessage Deserialise(std::span<std::byte> data);
};

struct GetRequest : Message {

};

struct GetResponse : Message {

};

struct PutRequest : Message {

};

struct PutResponse : Message {

};

struct TransferKeysRequest : Message {

};

struct TransferKeysResponse : Message {

};

struct ErrorResponse : Message {

};

MessageType GetMessageType(std::span<std::byte> data);
std::vector<std::byte> ReadMessagePayload(std::span<std::byte> data);

} // namespace tsc::msg

#endif // MESSAGE_H