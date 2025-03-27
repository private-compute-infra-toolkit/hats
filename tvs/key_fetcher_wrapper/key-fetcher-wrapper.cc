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

#include "tvs/key_fetcher_wrapper/key-fetcher-wrapper.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "key_manager/key-fetcher.h"
#include "key_manager/test-key-fetcher.h"
#include "tvs/key_fetcher_wrapper/src/key_fetcher.rs.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs::trusted {

namespace {

absl::string_view RustSliceToStringView(rust::Slice<const uint8_t> slice) {
  return absl::string_view(reinterpret_cast<const char*>(slice.data()),
                           slice.size());
}

}  // namespace

KeyFetcherWrapper::KeyFetcherWrapper(
    std::unique_ptr<key_manager::KeyFetcher> key_fetcher)
    : key_fetcher_(std::move(key_fetcher)) {}

VecU8Result KeyFetcherWrapper::GetPrimaryPrivateKey() const {
  absl::StatusOr<std::string> key = key_fetcher_->GetPrimaryPrivateKey();
  if (!key.ok()) {
    return {
        .error = absl::StrCat("Failed to get primary private key: ",
                              key.status().ToString()),
    };
  }
  rust::Vec<uint8_t> v;
  std::move(key->begin(), key->end(), std::back_inserter(v));
  return VecU8Result{
      .value = std::move(v),
  };
}

VecU8Result KeyFetcherWrapper::GetSecondaryPrivateKey() const {
  absl::StatusOr<std::string> key = key_fetcher_->GetSecondaryPrivateKey();
  if (!key.ok()) {
    return {
        .error = absl::StrCat("Failed to get secondary private key: ",
                              key.status().ToString()),
    };
  }
  rust::Vec<uint8_t> v;
  std::move(key->begin(), key->end(), std::back_inserter(v));
  return {
      .value = std::move(v),
  };
}

VecU8Result KeyFetcherWrapper::UserIdForAuthenticationKey(
    rust::Slice<const uint8_t> public_key) const {
  absl::StatusOr<std::string> user_id =
      key_fetcher_->UserIdForAuthenticationKey(std::string(
          reinterpret_cast<const char*>(public_key.data()), public_key.size()));
  if (!user_id.ok()) {
    return {
        .error = absl::StrCat("Failed to lookup user: ", user_id.status()),
    };
  }
  rust::Vec<uint8_t> v;
  std::move(user_id->begin(), user_id->end(), std::back_inserter(v));
  return {
      .value = std::move(v),
  };
}

VecU8Result KeyFetcherWrapper::GetSecretsForUserId(
    rust::Slice<const uint8_t> user_id) const {
  absl::StatusOr<std::vector<key_manager::Secret>> secrets =
      key_fetcher_->GetSecretsForUserId(std::string(
          reinterpret_cast<const char*>(user_id.data()), user_id.size()));
  if (!secrets.ok()) {
    return {
        .error = absl::StrCat("Failed to get secret: ", secrets.status()),
    };
  }
  std::string serialized_response;
  {
    VerifyReportResponse response;
    // Use non-const to enable effective use of std::move().
    for (key_manager::Secret& secret : *secrets) {
      Secret& tvs_secret = *response.add_secrets();
      *tvs_secret.mutable_key_id() = std::move(secret.key_id);
      *tvs_secret.mutable_public_key() = std::move(secret.public_key);
      *tvs_secret.mutable_private_key() = std::move(secret.private_key);
    }
    serialized_response = response.SerializeAsString();
  }
  rust::Vec<uint8_t> v;
  std::move(serialized_response.begin(), serialized_response.end(),
            std::back_inserter(v));
  return {
      .value = std::move(v),
  };
}

std::unique_ptr<KeyFetcherWrapper> CreateTestKeyFetcherWrapper(
    rust::Slice<const uint8_t> primary_private_key,
    rust::Slice<const uint8_t> secondary_private_key,
    rust::Slice<const uint8_t> user_id,
    rust::Slice<const uint8_t> user_authentication_public_key,
    rust::Slice<const uint8_t> key_id, rust::Slice<const uint8_t> user_secret,
    rust::Slice<const uint8_t> public_key) {
  return std::make_unique<KeyFetcherWrapper>(
      std::make_unique<key_manager::TestKeyFetcher>(
          RustSliceToStringView(primary_private_key),
          RustSliceToStringView(secondary_private_key),
          std::vector<key_manager::TestUserData>{{
              .user_id = std::string(RustSliceToStringView(user_id)),
              .user_authentication_public_key = std::string(
                  RustSliceToStringView(user_authentication_public_key)),
              .key_id = std::string(RustSliceToStringView(key_id)),
              .secret = std::string(RustSliceToStringView(user_secret)),
              .public_key = std::string(RustSliceToStringView(public_key)),
          }}));
}

}  // namespace privacy_sandbox::tvs::trusted
