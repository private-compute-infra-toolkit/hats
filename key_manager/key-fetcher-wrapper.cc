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

#include <iostream>
#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "key_manager/key-fetcher.h"
#include "rust/cxx.h"

namespace privacy_sandbox::key_manager {

namespace {

absl::StatusOr<KeyFetcher*> GetKeyFetcher() {
  // Create a key fetcher instance only once and return the same object if the
  // function is called again.
  static absl::StatusOr<std::unique_ptr<KeyFetcher>> key_fetcher = [&]() {
    return KeyFetcher::Create();
  }();
  if (!key_fetcher.ok()) return key_fetcher.status();
  return key_fetcher->get();
}

}  // namespace

rust::Vec<uint8_t> GetSecret(rust::Str secret_id) {
  absl::StatusOr<KeyFetcher*> key_fetcher = GetKeyFetcher();
  if (!key_fetcher.ok()) {
    throw std::runtime_error(
        absl::StrCat("Failed to create key fetcher. ", key_fetcher.status()));
  }
  absl::StatusOr<std::string> secret =
      (*key_fetcher)->GetSecret(std::string(secret_id));
  if (!secret.ok()) {
    throw std::runtime_error(
        absl::StrCat("Failed to get secret: ", secret.status()));
  }
  rust::Vec<uint8_t> v;
  std::copy(secret->begin(), secret->end(), std::back_inserter(v));
  return v;
}

}  // namespace privacy_sandbox::key_manager
