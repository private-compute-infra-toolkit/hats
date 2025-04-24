// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HATS_CACHE_EXPIRING_CACHE_H_
#define HATS_CACHE_EXPIRING_CACHE_H_

#include <memory>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "cache/interface.h"

namespace privacy_sandbox::cache {

// A thread-safe cache implementation where entries expire after a
// specified time-to-live (TTL).
//
// Implements the CacheInterface. This cache uses an absl::Mutex for thread
// safety and stores values along with their expiration timestamps. Expired
// entries are removed during lookup operations or when overwritten by Insert.
//
// Example:
//    ExpiringCache<int, std::string> cache(absl::Seconds(5));
//    cache.Insert(1, std::make_unique<std::string>("one"));
//    cache.Insert(2, std::make_unique<std::string>("two"));
//
//    std::shared_ptr<std::string> value = cache.Lookup(1);
//    if (value != nullptr) {
//      std::cout << *value << std::endl;
//    }
//
//    // Wait for the cache to expire
//    absl::SleepFor(absl::Seconds(6));
//
//    std::shared_ptr<std::string> value = cache.Lookup(1);
//    if (value == nullptr) {
//      std::cout << "Expired" << std::endl;
//    }
template <typename Key, typename Value>
class ExpiringCache final : public CacheInterface<Key, Value> {
 public:
  explicit ExpiringCache(absl::Duration cache_ttl) : cache_ttl_(cache_ttl) {}

  // Looks up a value associated with the given key.
  //
  // Acquires a lock, checks if the key exists, and verifies if the entry has
  // expired based on the insertion time and the configured TTL. If the entry
  // is found but expired, it is removed from the cache as a side effect.
  std::shared_ptr<const Value> Lookup(const Key& key) override
      ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
      if (absl::Now() < it->second.second) {
        return it->second.first;
      } else {
        // Entry expired, remove it.
        cache_.erase(it);
      }
    }
    return nullptr;
  }

  // Inserts or updates a key-value pair in the cache.
  //
  // Acquires a lock and stores the value along with its calculated expiration
  // time (current time + TTL). Takes ownership of the provided unique_ptr.
  // If the key already exists, its value and expiration time are overwritten.
  void Insert(const Key& key, std::unique_ptr<Value> value) override
      ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    cache_[key] = std::make_pair(std::shared_ptr<const Value>(std::move(value)),
                                 absl::Now() + cache_ttl_);
  }

  // Removes the entry associated with the given key, if it exists.
  //
  // Acquires a lock and removes the key-value pair from the cache.
  void Erase(const Key& key) override ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    cache_.erase(key);
  }

  // Returns the current number of entries in the cache.
  //
  // Acquires a lock to safely read the size.
  int64_t Size() const ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    return cache_.size();
  }

  // Removes all entries from the cache.
  //
  // Acquires a lock to safely clear the cache.
  void Clear() ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    cache_.clear();
  }

  // Removes all expired entries from the cache.
  //
  // Acquires a lock, iterates through the cache, and removes entries whose
  // expiration time is in the past relative to the time this function is
  // called.
  void CleanExpired() ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    const absl::Time now = absl::Now();

    absl::erase_if(cache_, [now](const auto& item) {
      return now >= item.second.second;  // Return true if expired
    });
  }

 private:
  absl::flat_hash_map<Key, std::pair<std::shared_ptr<const Value>, absl::Time>>
      cache_ ABSL_GUARDED_BY(mu_);
  mutable absl::Mutex mu_;
  absl::Duration cache_ttl_;
};

}  // namespace privacy_sandbox::cache
#endif  // HATS_CACHE_EXPIRING_CACHE_H_
