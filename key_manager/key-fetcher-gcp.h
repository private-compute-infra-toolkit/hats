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

#ifndef HATS_KEY_MANAGER_KEY_FETCHER_GCP_H_
#define HATS_KEY_MANAGER_KEY_FETCHER_GCP_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/spanner/client.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/key-fetcher.h"

namespace privacy_sandbox::key_manager {

class KeyFetcherGcp : public KeyFetcher {
 public:
  KeyFetcherGcp() = delete;
  // For unit-tests only.
  static std::unique_ptr<KeyFetcher> Create(
      google::cloud::kms_v1::v2_36::KeyManagementServiceClient client,
      google::cloud::spanner::Client spanner_client);
  KeyFetcherGcp(absl::string_view project_id, absl::string_view instance_id,
                absl::string_view database_id);

  absl::StatusOr<std::string> GetPrimaryPrivateKey() override;

  absl::StatusOr<std::string> GetSecondaryPrivateKey() override;

  absl::StatusOr<std::string> UserIdForAuthenticationKey(
      absl::string_view public_key) override;

  absl::StatusOr<std::vector<Secret>> GetSecretsForUserId(
      absl::string_view user_id) override;

  absl::StatusOr<bool> MaybeAcquireLock(absl::string_view user_id) override;

 private:
  // For unit-tests only.
  KeyFetcherGcp(google::cloud::kms_v1::v2_36::KeyManagementServiceClient client,
                google::cloud::spanner::Client spanner_client);

  privacy_sandbox::key_manager::GcpKmsClient gcp_kms_client_;
  google::cloud::spanner::Client spanner_client_;
};

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_KEY_FETCHER_GCP_H_
