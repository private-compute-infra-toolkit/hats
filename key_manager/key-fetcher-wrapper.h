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

#ifndef HATS_KEY_MANAGER_KEY_FETCHER_WRAPPER_H_
#define HATS_KEY_MANAGER_KEY_FETCHER_WRAPPER_H_
#include <string>

#include "include/cxx.h"
#include "key_manager/rust-key-fetcher.rs.h"

namespace privacy_sandbox::key_manager {

// Wrapper functions around `KeyFetcher` methods to make it usable to Rust code

IntResult UserIdForAuthenticationKey(rust::Slice<const uint8_t> public_key);

VecU8Result GetSecretsForUserId(int64_t user_id);

bool MaybeAcquireLock(int64_t user_id);

// Allow registration of a KeyFetcher to be used in test.
// The registered KeyFetcher echos back the `username` as the secret.
// Note, we only allow registration once to avoid unexpected behavior just
// in case tests are run in parallel.
// The user should call this function before any call to GetSecret(), so either
// in the test module initialization or make sure to call it in every unit test.
void RegisterEchoKeyFetcherForTest();

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_KEY_FETCHER_WRAPPER_H_
