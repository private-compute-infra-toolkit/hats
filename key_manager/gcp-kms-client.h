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

#ifndef HATS_KEY_MANAGER_GCP_KEY_MANAGER_H
#define HATS_KEY_MANAGER_GCP_KEY_MANAGER_H

#include <string>

#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "key_manager/kms-client.h"

namespace pcit::key_manager {
class GcpKmsClient : public KmsClient {
 public:
  explicit GcpKmsClient(
      google::cloud::kms_v1::v2_36::KeyManagementServiceClient client);
  GcpKmsClient() = delete;

  absl::StatusOr<PublicKey> GetPublicKey(absl::string_view key_id) override;
  absl::StatusOr<CryptoKey> CreateAsymmetricKey(
      absl::string_view parent, absl::string_view key_id) override;
  absl::StatusOr<std::string> EncryptData(
      absl::string_view key_id, absl::string_view plaintext,
      absl::string_view associated_data) override;
  absl::StatusOr<std::string> DecryptData(
      absl::string_view key_id, absl::string_view ciphertext,
      absl::string_view associated_data) override;

 private:
  google::cloud::kms_v1::v2_36::KeyManagementServiceClient client_;
};

}  // namespace pcit::key_manager

#endif  // HATS_KEY_MANAGER_GCP_KEY_MANAGER_
