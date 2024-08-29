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

#include "key_manager/key-fetcher-wrapper.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "include/cxx.h"
#include "key_manager/key-fetcher.h"
#include "key_manager/rust-key-fetcher.rs.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::key_manager {

namespace {

absl::Mutex key_fetcher_registration_mu(absl::kConstInit);
KeyFetcher* registered_key_fetcher
    ABSL_GUARDED_BY(key_fetcher_registration_mu) = nullptr;

// Return a registered KeyFetcher if there is any; otherwise, create
// and return the default KeyFetcher.
KeyFetcher* RegisteredKeyFetcherOrDefault() {
  absl::MutexLock lock(&key_fetcher_registration_mu);
  if (registered_key_fetcher == nullptr) {
    // Create a key fetcher instance only once and return the same object if the
    // function is called again.
    registered_key_fetcher = KeyFetcher::Create().release();
  }
  return registered_key_fetcher;
}

class EchoKeyFetcher final : public KeyFetcher {
 public:
  EchoKeyFetcher() {
    if (!absl::HexStringToBytes(
            "04f3099a8ebcb494430958bd39b246255589b44c60bceb2ef392ffbb7529962c05"
            "e94895665cc7e1a54f730480f50c523f7bc90b70b3a12ab7850293290d2e32c8",
            &test_client_authentication_key_)) {
      LOG(ERROR) << "Failed to convert test key from hex to bytes";
    }
  }

  absl::StatusOr<std::string> GetPrimaryPrivateKey() override {
    return absl::UnimplementedError("unimplemented.");
  }

  absl::StatusOr<std::string> GetSecondaryPrivateKey() override {
    return absl::UnimplementedError("unimplemented.");
  }

  absl::StatusOr<int64_t> UserIdForAuthenticationKey(
      absl::string_view public_key) override {
    if (public_key == test_client_authentication_key_) {
      return 1;
    }
    return absl::NotFoundError("Cannot find public key");
  }

  absl::StatusOr<std::vector<Secret>> GetSecretsForUserId(
      int64_t user_id) override {
    return std::vector<Secret>{{
        .key_id = 64,
        .public_key = absl::StrCat(user_id, "-public-key"),
        .private_key = absl::StrCat(user_id, "-secret"),
    }};
  }

 private:
  std::string test_client_authentication_key_;
};

}  // namespace

IntResult UserIdForAuthenticationKey(rust::Slice<const uint8_t> public_key) {
  KeyFetcher* key_fetcher = RegisteredKeyFetcherOrDefault();
  absl::StatusOr<int64_t> user_id =
      key_fetcher->UserIdForAuthenticationKey(std::string(
          reinterpret_cast<const char*>(public_key.data()), public_key.size()));
  if (!user_id.ok()) {
    return IntResult{
        .error = absl::StrCat("Failed to lookup user: ", user_id.status()),
    };
  }
  return IntResult{
      .value = *std::move(user_id),
  };
}

VecU8Result GetSecretsForUserId(int64_t user_id) {
  KeyFetcher* key_fetcher = RegisteredKeyFetcherOrDefault();
  absl::StatusOr<std::vector<Secret>> secrets =
      key_fetcher->GetSecretsForUserId(user_id);
  if (!secrets.ok()) {
    return VecU8Result{
        .error = absl::StrCat("Failed to get secret: ", secrets.status()),
    };
  }
  std::string serialized_response;
  {
    tvs::VerifyReportResponse response;
    // Use non-const to enable effective use of std::move().
    for (Secret& secret : *secrets) {
      tvs::Secret& tvs_secret = *response.add_secrets();
      tvs_secret.set_key_id(secret.key_id);
      *tvs_secret.mutable_public_key() = std::move(secret.public_key);
      *tvs_secret.mutable_private_key() = std::move(secret.private_key);
    }
    serialized_response = response.SerializeAsString();
  }
  rust::Vec<uint8_t> v;
  std::copy(serialized_response.begin(), serialized_response.end(),
            std::back_inserter(v));
  return VecU8Result{
      .value = std::move(v),
  };
}

void RegisterEchoKeyFetcherForTest() {
  absl::MutexLock lock(&key_fetcher_registration_mu);
  if (registered_key_fetcher != nullptr) {
    return;
  }
  // Yes, we create and release as we really do not like to use `new()`.
  // Although this is effectively using `new()`.
  registered_key_fetcher = std::make_unique<EchoKeyFetcher>().release();
}

}  // namespace privacy_sandbox::key_manager
