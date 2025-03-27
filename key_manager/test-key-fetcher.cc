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

#include "key_manager/test-key-fetcher.h"

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace privacy_sandbox::key_manager {

TestKeyFetcher::TestKeyFetcher(absl::string_view primary_private_key,
                               absl::string_view secondary_private_key,
                               const std::vector<TestUserData>& user_data)
    : primary_private_key_(primary_private_key),
      secondary_private_key_(secondary_private_key),
      user_data_(user_data) {}

absl::StatusOr<std::string> TestKeyFetcher::GetPrimaryPrivateKey() {
  return primary_private_key_;
}

absl::StatusOr<std::string> TestKeyFetcher::GetSecondaryPrivateKey() {
  return secondary_private_key_;
}

absl::StatusOr<std::string> TestKeyFetcher::UserIdForAuthenticationKey(
    absl::string_view user_authentication_public_key) {
  for (const TestUserData& test_user_data : user_data_) {
    if (test_user_data.user_authentication_public_key ==
            user_authentication_public_key &&
        !test_user_data.user_authentication_public_key.empty()) {
      return test_user_data.user_id;
    }
  }
  return absl::UnauthenticatedError("unregistered or expired public key.");
}

absl::StatusOr<std::vector<Secret>> TestKeyFetcher::GetSecretsForUserId(
    absl::string_view user_id) {
  std::vector<Secret> result;
  for (const TestUserData& test_user_data : user_data_) {
    if (test_user_data.user_id == user_id && !test_user_data.secret.empty()) {
      result.push_back({
          .key_id = test_user_data.key_id,
          .public_key = test_user_data.public_key,
          .private_key = test_user_data.secret,
      });
    }
  }
  if (result.empty()) {
    return absl::NotFoundError("Cannot find secret for the user");
  }
  return result;
}

absl::StatusOr<bool> TestKeyFetcher::MaybeAcquireLock(
    absl::string_view user_id) {
  return absl::UnimplementedError("unimplemented");
}

}  // namespace privacy_sandbox::key_manager
