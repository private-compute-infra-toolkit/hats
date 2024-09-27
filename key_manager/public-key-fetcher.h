// Copyright 2024 Google LLC.
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

#ifndef HATS_KEY_MANAGER_PUBLIC_KEY_FETCHER_H_
#define HATS_KEY_MANAGER_PUBLIC_KEY_FETCHER_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"

namespace privacy_sandbox::key_manager {

struct PerOriginPublicKey {
  int64_t key_id;
  std::string public_key;
  std::string origin;
  bool operator==(const PerOriginPublicKey& rhs) const {
    return key_id == rhs.key_id && public_key == rhs.public_key &&
           origin == rhs.origin;
  }
};

// PublicKeyFetcher is not allowed to talk to KMS.
class PublicKeyFetcher {
 public:
  static std::unique_ptr<PublicKeyFetcher> Create();
  virtual ~PublicKeyFetcher() = default;
  // Fetch the last public keys for each user ordered by Secret
  // UpdateTimestamp.
  virtual absl::StatusOr<std::vector<PerOriginPublicKey>>
  GetLatestPublicKeys() = 0;
};

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_PUBLIC_KEY_FETCHER_H_
