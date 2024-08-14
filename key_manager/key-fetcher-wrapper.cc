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

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "key_manager/key-fetcher.h"
#include "rust/cxx.h"

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
  absl::StatusOr<std::string> GetPrimaryPrivateKey() override {
    return absl::UnimplementedError("unimplemented.");
  }
  absl::StatusOr<std::string> GetSecondaryPrivateKey() override {
    return absl::UnimplementedError("unimplemented.");
  }
  absl::StatusOr<std::string> GetSecret(absl::string_view user_name) override {
    return absl::StrCat(user_name, "-secret");
  }
  absl::StatusOr<int64_t> UserIdForAuthenticationKey(
      absl::string_view public_key) override {
    return 0;
  }
  absl::StatusOr<std::string> GetSecretForUserId(int64_t user_id) override {
    return absl::StrCat(user_id, "-secret");
  }
};

}  // namespace

rust::Vec<uint8_t> GetSecret(rust::Str username) {
  KeyFetcher* key_fetcher = RegisteredKeyFetcherOrDefault();
  absl::StatusOr<std::string> secret =
      key_fetcher->GetSecret(std::string(username));
  if (!secret.ok()) {
    throw std::runtime_error(
        absl::StrCat("Failed to get secret: ", secret.status()));
  }
  rust::Vec<uint8_t> v;
  std::copy(secret->begin(), secret->end(), std::back_inserter(v));
  return v;
}

int64_t UserIdForAuthenticationKey(rust::Slice<const uint8_t> public_key) {
  KeyFetcher* key_fetcher = RegisteredKeyFetcherOrDefault();
  absl::StatusOr<int64_t> user_id =
      key_fetcher->UserIdForAuthenticationKey(std::string(
          reinterpret_cast<const char*>(public_key.data()), public_key.size()));
  if (!user_id.ok()) {
    throw std::runtime_error(
        absl::StrCat("Failed to lookup user: ", user_id.status()));
  }
  return *std::move(user_id);
}

rust::Vec<uint8_t> GetSecretForUserId(int64_t user_id) {
  KeyFetcher* key_fetcher = RegisteredKeyFetcherOrDefault();
  absl::StatusOr<std::string> secret = key_fetcher->GetSecretForUserId(user_id);
  if (!secret.ok()) {
    throw std::runtime_error(
        absl::StrCat("Failed to get secret: ", secret.status()));
  }
  rust::Vec<uint8_t> v;
  std::copy(secret->begin(), secret->end(), std::back_inserter(v));
  return v;
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
