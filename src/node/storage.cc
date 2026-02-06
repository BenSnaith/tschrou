#include "storage.h"
#include "util/hash.h"

namespace tsc::node {
using namespace tsc::hsh;
void Storage::Put(const std::string& key, const std::string& value) {
  std::lock_guard lock(mutex_);
  data_[key] = value;
}

std::optional<std::string> Storage::Get(const std::string& key) const {
  std::lock_guard lock(mutex_);
  auto it = data_.find(key);
  if(it != data_.end()) {
    return it->second;
  }
  return std::nullopt;
}

bool Storage::Remove(const std::string& key) {
  std::lock_guard lock(mutex_);
  return data_.erase(key) > 0;
}

bool Storage::Contains(const std::string& key) const {
  std::lock_guard lock(mutex_);
  return data_.find(key) != data_.end();
}

size_t Storage::Size() const {
  std::lock_guard lock(mutex_);
  return data_.size();
}

std::vector<std::string> Storage::Keys() const {
  std::lock_guard lock(mutex_);
  std::vector<std::string> keys;
  keys.reserve(data_.size());
  for (const auto& [key, value] : data_) {
    keys.push_back(key);
  }
  return keys;
}

std::vector<std::pair<std::string, std::string>> Storage::GetRange(
    KeyID start, KeyID end) const {
  std::lock_guard lock(mutex_);
  KeySet result;

  for (const auto& [key, value] : data_) {
    KeyID key_id = Hash::HashKey(key);
    if (InRangeExclusiveInclusive(key_id, start, end)) {
      result.emplace_back(key, value);
    }
  }

  return result;
}

std::vector<std::pair<std::string, std::string>> Storage::RemoveRange(
    KeyID start, KeyID end) {
  std::lock_guard lock(mutex_);
  KeySet result;
  std::vector<std::string> keys_to_remove;

  for (const auto& [key, value] : data_) {
    KeyID key_id = Hash::HashKey(key);
    if (InRangeExclusiveInclusive(key_id, start, end)) {
      result.emplace_back(key, value);
      keys_to_remove.push_back(key);
    }
  }

  for (const auto& key : keys_to_remove) {
    data_.erase(key);
  }

  return result;
}

void Storage::PutAll(
    const std::vector<std::pair<std::string, std::string>>& items) {
  std::lock_guard lock(mutex_);
  for(const auto& [key, value] : items) {
    data_[key] = value;
  }
}

void Storage::Clear() {
  std::lock_guard lock(mutex_);
  data_.clear();
}
} // namespace tsc::node