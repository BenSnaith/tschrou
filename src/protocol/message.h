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
  [[nodiscard]] virtual std::vector<std::byte> Serialise() const = 0;

  virtual ~Message() = default;

  MessageType type_;
};

struct FindSuccessorRequest : Message {
  FindSuccessorRequest() { type_ = MessageType::kFindSuccessorRequest; }
  explicit FindSuccessorRequest(NodeID id) : id_(id) {
    type_ = MessageType::kFindSuccessorRequest;
  }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static FindSuccessorRequest Deserialise(std::span<std::byte> data);

  NodeID id_;
};

struct FindSuccessorResponse : Message {
  FindSuccessorResponse() { type_ = MessageType::kFindSuccessorResponse; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static FindSuccessorResponse Deserialise(std::span<std::byte> data);

  NodeInfo successor_;
  bool found_;
};

struct GetPredecessorRequest : Message {
  GetPredecessorRequest() { type_ = MessageType::kGetPredecessorRequest; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static GetPredecessorRequest Deserialise(std::span<std::byte> data);
};

struct GetPredecessorResponse : Message {
  GetPredecessorResponse() { type_ = MessageType::kGetPredecessorResponse; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static GetPredecessorResponse Deserialise(std::span<std::byte> data);

  NodeInfo predecessor_;
  bool has_predecessor_;
};

struct NotifyMessage : Message {
  NotifyMessage() { type_ = MessageType::kNotify; }
  explicit NotifyMessage(const NodeInfo& node) : node_(node) {
    type_ = MessageType::kNotify;
  }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static NotifyMessage Deserialise(std::span<std::byte> data);

  NodeInfo node_;
};

struct NotifyAck : Message {
  NotifyAck() { type_ = MessageType::kNotifyAck; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static NotifyAck Deserialise(std::span<std::byte> data);

  bool accepted_;
};

struct PingMessage : Message {
  PingMessage() { type_ = MessageType::kPing; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static PingMessage Deserialise(std::span<std::byte> data);
};

struct PongMessage : Message {
  PongMessage() { type_ = MessageType::kPong; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static PongMessage Deserialise(std::span<std::byte> data);
};

struct GetRequest : Message {
  GetRequest() { type_ = MessageType::kGetRequest; }
  explicit GetRequest(const std::string& key) : key_(key) {}

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static GetRequest Deserialise(std::span<std::byte> data);

  std::string key_;
};

struct GetResponse : Message {
  GetResponse() { type_ = MessageType::kGetResponse; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static GetResponse Deserialise(std::span<std::byte> data);

  std::string value_;
  bool found_;
};

struct PutRequest : Message {
  PutRequest() { type_ = MessageType::kPutRequest; }
  PutRequest(const std::string& key, const std::string& value)
    : key_(key)
    , value_(value)
  { type_ = MessageType::kPutRequest; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static PutRequest Deserialise(std::span<std::byte> data);

  std::string key_;
  std::string value_;
};

struct PutResponse : Message {
  PutResponse() { type_ = MessageType::kPutResponse; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static PutResponse Deserialise(std::span<std::byte> data);

  bool success_;
};

struct TransferKeysRequest : Message {
  TransferKeysRequest() { type_ = MessageType::kTransferKeysRequest; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static TransferKeysRequest Deserialise(std::span<std::byte> data);

  NodeID start_;
  NodeID end_;
};

struct TransferKeysResponse : Message {
  TransferKeysResponse() { type_ = MessageType::kTransferKeysResponse; }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static TransferKeysResponse Deserialise(std::span<std::byte> data);

  std::vector<std::pair<std::string, std::string>> keys_;
};

struct ErrorResponse : Message {
  ErrorResponse() { type_ = MessageType::kErrorResponse; }
  explicit ErrorResponse(const std::string& msg) : error_message_(msg) {
    type_ = MessageType::kErrorResponse;
  }

  [[nodiscard]] std::vector<std::byte> Serialise() const override;
  static ErrorResponse Deserialise(std::span<std::byte> data);

  std::string error_message_;
};

Result<MessageType> GetMessageType(std::span<std::byte> data);
std::vector<std::byte> ReadMessagePayload(std::span<std::byte> data);

} // namespace tsc::msg

#endif // MESSAGE_H