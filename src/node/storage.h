#ifndef STORAGE_H
#define STORAGE_H

#include <unordered_map>
#include <string>
#include <optional>
#include <mutex>
#include <vector>

#include "types/types.h"

namespace tsc::node {
using namespace tsc::type;
class Storage {
public:
  Storage() = default;

  void Put(const std::string& key, const std::string& value);

  std::optional<std::string> Get(const std::string& key) const;

  bool Remove(const std::string& key);

  bool Contains(const std::string& key) const;

  size_t Size() const;

  std::vector<std::string> Keys() const;

  std::vector<std::pair<std::string, std::string>> GetRange(
    KeyID start,
    KeyID end
  ) const;

  std::vector<std::pair<std::string, std::string>> RemoveRange(
    KeyID start,
    KeyID end
  );

  void PutAll(const std::vector<std::pair<std::string, std::string>>& items);

  void Clear();

private:
  std::unordered_map<std::string, std::string> data_;
  mutable std::mutex mutex_;
};
} // namespace tsc::node

#endif