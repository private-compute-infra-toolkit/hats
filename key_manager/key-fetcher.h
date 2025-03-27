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

#ifndef HATS_KEY_MANAGER_KEY_FETCHER_H_
#define HATS_KEY_MANAGER_KEY_FETCHER_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace privacy_sandbox::key_manager {

struct Secret {
  int64_t key_id;
  std::string public_key;
  std::string private_key;
};

class KeyFetcher {
 public:
  static std::unique_ptr<KeyFetcher> Create();
  virtual ~KeyFetcher() = default;
  // The primary private key used for the noise protocol.
  virtual absl::StatusOr<std::string> GetPrimaryPrivateKey() = 0;
  // The secondary private key used for the noise protocol.
  virtual absl::StatusOr<std::string> GetSecondaryPrivateKey() = 0;
  // Find the user id owning the authentication key.
  virtual absl::StatusOr<std::string> UserIdForAuthenticationKey(
      absl::string_view public_key) = 0;
  // Find secrets for `user_id`.
  virtual absl::StatusOr<std::vector<Secret>> GetSecretsForUserId(
      absl::string_view user_id) = 0;
  // Returns true iff the lock was successfully acquired and it's OK to proceed
  // with key generation.
  virtual absl::StatusOr<bool> MaybeAcquireLock(absl::string_view user_id) = 0;
};

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_KEY_FETCHER_H_
