/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HATS_KEY_MANAGER_TEST_KEY_FETCHER_H_
#define HATS_KEY_MANAGER_TEST_KEY_FETCHER_H_

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "key_manager/key-fetcher.h"

namespace privacy_sandbox::key_manager {

// Store data for every user.
struct TestUserData {
  // User ID.
  std::string user_id;
  // Public key used to authenticated `user_id`.
  std::string user_authentication_public_key;
  // Key ID
  std::string key_id;
  // Secret for `user_id`.
  std::string secret;
  // Public part of the secret. If secret is a private key, then this is the
  // public counterpart.
  std::string public_key;
};

// Key fetcher to be used in unit-tests.
// The class accept keys in byte format.
class TestKeyFetcher final : public KeyFetcher {
 public:
  TestKeyFetcher() = delete;
  TestKeyFetcher(absl::string_view primary_private_key,
                 absl::string_view secondary_private_key,
                 const std::vector<TestUserData>& user_data);
  absl::StatusOr<std::string> GetPrimaryPrivateKey() override;
  absl::StatusOr<std::string> GetSecondaryPrivateKey() override;
  absl::StatusOr<std::string> UserIdForAuthenticationKey(
      absl::string_view public_key) override;
  absl::StatusOr<std::vector<Secret>> GetSecretsForUserId(
      absl::string_view user_id) override;
  absl::StatusOr<bool> MaybeAcquireLock(absl::string_view user_id) override;

 private:
  std::string primary_private_key_;
  std::string secondary_private_key_;
  std::vector<TestUserData> user_data_;
};

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_TEST_KEY_FETCHER_H_
