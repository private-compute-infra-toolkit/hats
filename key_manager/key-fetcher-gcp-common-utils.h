// Copyright 2025 Google LLC.
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

#ifndef HATS_KEY_MANAGER_KEY_FETCHER_GCP_COMMON_UTILS_H_
#define HATS_KEY_MANAGER_KEY_FETCHER_GCP_COMMON_UTILS_H_

#include <string>

#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "crypto/secret-data.h"
#include "google/cloud/spanner/client.h"
#include "key_manager/gcp-kms-client.h"

namespace pcit::key_manager {
struct Keys {
  std::string kek;
  std::string dek;
  int64_t key_id;
  std::string public_key;
  std::string private_key;
};

absl::StatusOr<Keys> WrappedEcKeyFromSpanner(
    absl::string_view key_name, google::cloud::spanner::Client& client);

absl::StatusOr<crypto::SecretData> UnwrapSecret(
    absl::string_view associated_data,
    pcit::key_manager::GcpKmsClient& gcp_kms_client, const Keys& keys);
}  // namespace pcit::key_manager

#endif  // HATS_KEY_MANAGER_KEY_FETCHER_GCP_COMMON_UTILS_H_
