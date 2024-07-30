// LOCAL_GOOGLE_HOME_ALWABEL_HATS_KEYS_HATS_KEY_MANAGER_KEY_FETCHER_GCP_H_
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

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/key-fetcher.h"

ABSL_DECLARE_FLAG(std::string, project_id);
ABSL_DECLARE_FLAG(std::string, location_id);
ABSL_DECLARE_FLAG(std::string, key_ring_id);
ABSL_DECLARE_FLAG(std::string, private_key_id);
ABSL_DECLARE_FLAG(std::string, secret_id);
ABSL_DECLARE_FLAG(std::string, primary_private_key);
ABSL_DECLARE_FLAG(std::string, secret);

namespace privacy_sandbox::key_manager {

class KeyFetcherGcp : public KeyFetcher {
 public:
  KeyFetcherGcp() = delete;

  KeyFetcherGcp(const std::string& project_id, const std::string& location_id,
                const std::string& key_ring_id,
                const std::string& private_key_id, const std::string& secret_id,
                const std::string& primary_private_key,
                const std::string& secret);

  // For unit-tests only.
  KeyFetcherGcp(
      const std::string& project_id, const std::string& location_id,
      const std::string& key_ring_id, const std::string& private_key_id,
      const std::string& secret_id, const std::string& primary_private_key,
      const std::string& secret,
      google::cloud::kms_v1::v2_25::KeyManagementServiceClient client);
  // For unit-tests only.
  static std::unique_ptr<KeyFetcher> Create(
      google::cloud::kms_v1::v2_25::KeyManagementServiceClient client);

  absl::StatusOr<std::string> GetPrimaryPrivateKey() override;

  absl::StatusOr<std::string> GetSecondaryPrivateKey() override;

  absl::StatusOr<std::string> GetSecret(const std::string& secret_id) override;

 private:
  const std::string project_id_;
  const std::string location_id_;
  const std::string key_ring_id_;
  const std::string private_key_id_;
  const std::string secret_id_;
  const std::string primary_private_key_;
  const std::string secret_;
  privacy_sandbox::key_manager::GcpKmsClient gcp_kms_client_;
};

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_KEY_FETCHER_GCP_H_
