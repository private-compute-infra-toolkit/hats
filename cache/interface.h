// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HATS_CACHE_INTERFACE_H_
#define HATS_CACHE_INTERFACE_H_

#include <memory>

namespace privacy_sandbox::cache {

template <typename Key, typename Value>
class CacheInterface {
 public:
  virtual ~CacheInterface() = default;

  virtual std::shared_ptr<const Value> Lookup(const Key& key) = 0;
  virtual void Insert(const Key& key, std::unique_ptr<Value> value) = 0;
  virtual void Erase(const Key& key) = 0;
};

}  // namespace privacy_sandbox::cache
#endif  // HATS_CACHE_INTERFACE_H_
