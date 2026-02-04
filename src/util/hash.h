#ifndef HASH_H
#define HASH_H

#include <openssl/sha.h>
#include <cstring>

#include "types/types.h"

namespace tsc::hsh {
using namespace tsc::type;
class Hash {
public:
  static KeyID HashKey(const std::string& key) {
    return ComputeHash(key);
  }

  static NodeID HashNode(const NodeAddress& address) {
    return ComputeHash(address.ToString());
  }

  static u32 ComputeHash(const std::string& input) {
    u8 hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const u8*>(input.c_str()), input.length(), hash);

    u32 result;
    std::memcpy(&result, hash, sizeof(result));
    return result;
  }
};
} // namespace tsc::hsh

#endif // HASH_H
