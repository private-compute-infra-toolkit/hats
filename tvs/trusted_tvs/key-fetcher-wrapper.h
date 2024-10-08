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

#ifndef HATS_TVS_TRUSTED_TVS_KEY_FETCHER_WRAPPER_H_
#define HATS_TVS_TRUSTED_TVS_KEY_FETCHER_WRAPPER_H_

#include <memory>

#include "include/cxx.h"
#include "key_manager/key-fetcher.h"

namespace privacy_sandbox::tvs::trusted {

// Forward declaration for the shared types. We cannot include the header
// generated from rust as we are redefining KeyFetcherWrapper in there.
struct IntResult;
struct VecU8Result;

// Wrapper class around `key_manager::KeyFetcher` methods to make it usable to
// Rust code. Due to the limitation in the FFI, methods exported to rust has to
// be marked as `const` even if they are not.
class KeyFetcherWrapper {
 public:
  explicit KeyFetcherWrapper(
      std::unique_ptr<key_manager::KeyFetcher> key_fetcher);
  KeyFetcherWrapper() = delete;

  VecU8Result GetPrimaryPrivateKey() const;

  VecU8Result GetSecondaryPrivateKey() const;

  IntResult UserIdForAuthenticationKey(
      rust::Slice<const uint8_t> public_key) const;

  VecU8Result GetSecretsForUserId(int64_t user_id) const;

  bool MaybeAcquireLock(int64_t user_id);

 private:
  std::unique_ptr<key_manager::KeyFetcher> key_fetcher_;
};

std::unique_ptr<KeyFetcherWrapper> CreateTestKeyFetcherWrapper(
    rust::Slice<const uint8_t> primary_private_key,
    rust::Slice<const uint8_t> secondary_private_key, int64_t user_id,
    rust::Slice<const uint8_t> user_authentication_public_key, int64_t key_id,
    rust::Slice<const uint8_t> secret, rust::Slice<const uint8_t> public_key);

}  // namespace privacy_sandbox::tvs::trusted

#endif  // HATS_TVS_TRUSTED_TVS_KEY_FETCHER_WRAPPER_H_
