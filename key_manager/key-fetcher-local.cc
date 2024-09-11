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

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "key_manager/key-fetcher.h"

ABSL_FLAG(std::string, primary_private_key, "",
          "Primary private key for KK-Noise handshake protocol.");
ABSL_FLAG(std::string, secondary_private_key, "",
          "Secondary private key for KK-Noise handshake protocol.");
ABSL_FLAG(int64_t, user_key_id, 64,
          "ID for the secret, which is a full or partial private HPKEY key.");
ABSL_FLAG(std::string, user_public_key, "some public key",
          "Public part of the secret.");
ABSL_FLAG(std::string, user_secret, "736563726574",
          "A secret to be returned to client passing attestation validation.");
ABSL_FLAG(
    std::string, user_authentication_public_key, "",
    "Public portion of the key used by the user to authenticate with TVS.");

namespace privacy_sandbox::key_manager {

class KeyFetcherLocal : public KeyFetcher {
 public:
  KeyFetcherLocal() = delete;

  KeyFetcherLocal(absl::string_view primary_private_key,
                  absl::string_view secondary_private_key, int64_t user_key_id,
                  absl::string_view user_public_key,
                  absl::string_view user_secret,
                  absl::string_view user_authentication_public_key)
      : primary_private_key_(primary_private_key),
        secondary_private_key_(secondary_private_key),
        user_key_id_(user_key_id),
        user_public_key_(user_public_key),
        user_secret_(user_secret),
        user_authentication_public_key_(user_authentication_public_key) {}

  absl::StatusOr<std::string> GetPrimaryPrivateKey() override {
    std::string primary_private_key_bytes;
    if (!absl::HexStringToBytes(primary_private_key_,
                                &primary_private_key_bytes)) {
      return absl::InvalidArgumentError(
          "Failed to parse the primary private key. Private keys should be "
          "formatted as hex "
          "string.");
    }
    return primary_private_key_bytes;
  }

  absl::StatusOr<std::string> GetSecondaryPrivateKey() override {
    if (secondary_private_key_.empty()) return secondary_private_key_;
    std::string secondary_private_key_bytes;
    if (!absl::HexStringToBytes(secondary_private_key_,
                                &secondary_private_key_bytes)) {
      return absl::InvalidArgumentError(
          "Failed to parse the secondary private key. Private keys should be "
          "formatted as hex "
          "string.");
    }
    return secondary_private_key_bytes;
  }

  absl::StatusOr<int64_t> UserIdForAuthenticationKey(
      absl::string_view public_key) override {
    std::string user_authentication_public_key_bytes;
    if (!absl::HexStringToBytes(user_authentication_public_key_,
                                &user_authentication_public_key_bytes)) {
      return absl::InvalidArgumentError(
          "Failed to parse the user authentication public key. The key should "
          "be "
          "formatted as hex "
          "string.");
    }
    if (public_key == user_authentication_public_key_bytes) {
      // Always return 0 because we only have one user.
      return 1;
    }
    return absl::UnauthenticatedError("unregistered or expired public key.");
  }

  absl::StatusOr<std::vector<Secret>> GetSecretsForUserId(
      int64_t user_id) override {
    if (user_id != 1) {
      return absl::NotFoundError(
          absl::StrCat("Cannot find user id '", user_id, "'"));
    }
    // Return the same secret since we have one user only in the local mode.
    std::string secret_bytes;
    if (!absl::HexStringToBytes(user_secret_, &secret_bytes)) {
      return absl::InvalidArgumentError(
          "Failed to parse the secret. Secrets should be "
          "formatted as hex "
          "string.");
    }
    return std::vector<Secret>{{
        .key_id = user_key_id_,
        .public_key = user_public_key_,
        .private_key = std::move(secret_bytes),
    }};
  }

  absl::StatusOr<bool> MaybeAcquireLock(int64_t user_id) { return false; }

 private:
  const std::string primary_private_key_;
  const std::string secondary_private_key_;
  int64_t user_key_id_;
  const std::string user_public_key_;
  const std::string user_secret_;
  const std::string user_authentication_public_key_;
};

std::unique_ptr<KeyFetcher> KeyFetcher::Create() {
  return std::make_unique<KeyFetcherLocal>(
      absl::GetFlag(FLAGS_primary_private_key),
      absl::GetFlag(FLAGS_secondary_private_key),
      absl::GetFlag(FLAGS_user_key_id), absl::GetFlag(FLAGS_user_public_key),
      absl::GetFlag(FLAGS_user_secret),
      absl::GetFlag(FLAGS_user_authentication_public_key));
}

}  // namespace privacy_sandbox::key_manager
