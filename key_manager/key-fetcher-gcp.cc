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

#include "key_manager/key-fetcher-gcp.h"

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "key_manager/gcp-kms-client.h"
#include "key_manager/key-fetcher.h"

ABSL_FLAG(std::string, project_id, "", "Project ID.");
ABSL_FLAG(std::string, location_id, "", "Location ID.");
ABSL_FLAG(std::string, key_ring_id, "", "Key Ring ID.");
ABSL_FLAG(std::string, private_key_id, "", "CryptoKey ID.");
ABSL_FLAG(std::string, secret_id, "", "Secret ID.");
ABSL_FLAG(std::string, primary_private_key, "",
          "Primary private key for NK-Noise handshake protocol.");
ABSL_FLAG(std::string, secret, "",
          "A secret to be returned to client passing attestation validation.");

namespace privacy_sandbox::key_manager {

KeyFetcherGcp::KeyFetcherGcp(const std::string& project_id,
                             const std::string& location_id,
                             const std::string& key_ring_id,
                             const std::string& private_key_id,
                             const std::string& secret_id,
                             const std::string& primary_private_key,
                             const std::string& secret)
    : project_id_(project_id),
      location_id_(location_id),
      key_ring_id_(key_ring_id),
      private_key_id_(private_key_id),
      secret_id_(secret_id),
      primary_private_key_(primary_private_key),
      secret_(secret),
      gcp_kms_client_(google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection())) {}

KeyFetcherGcp::KeyFetcherGcp(
    const std::string& project_id, const std::string& location_id,
    const std::string& key_ring_id, const std::string& private_key_id,
    const std::string& secret_id, const std::string& primary_private_key,
    const std::string& secret,
    google::cloud::kms_v1::v2_25::KeyManagementServiceClient client)
    : project_id_(project_id),
      location_id_(location_id),
      key_ring_id_(key_ring_id),
      private_key_id_(private_key_id),
      secret_id_(secret_id),
      primary_private_key_(primary_private_key),
      secret_(secret),
      gcp_kms_client_(google::cloud::kms_v1::KeyManagementServiceClient(
          std::move(client))) {}

absl::StatusOr<std::string> KeyFetcherGcp::GetPrimaryPrivateKey() {
  std::string encrypted_key;
  if (!absl::HexStringToBytes(primary_private_key_, &encrypted_key)) {
    return absl::InvalidArgumentError(
        "Failed to parse primary private key. The key should be in hex "
        "format");
  }

  return gcp_kms_client_.DecryptData(
      absl::StrCat("projects/", project_id_, "/locations/", location_id_,
                   "/keyRings/", key_ring_id_, "/cryptoKeys/", private_key_id_),
      encrypted_key);
}

absl::StatusOr<std::string> KeyFetcherGcp::GetSecondaryPrivateKey() {
  return absl::UnimplementedError("Unimplemented");
}

// We are ignoring secret_id right now since we only support one secret.
absl::StatusOr<std::string> KeyFetcherGcp::GetSecret(
    const std::string& secret_id) {
  std::string encrypted_secret;
  if (!absl::HexStringToBytes(secret_, &encrypted_secret)) {
    return absl::InvalidArgumentError(
        "Failed to parse secret key. The secret should be in hex format");
  }
  return gcp_kms_client_.DecryptData(
      absl::StrCat("projects/", project_id_, "/locations/", location_id_,
                   "/keyRings/", key_ring_id_, "/cryptoKeys/", secret_id_),
      encrypted_secret);
}

std::unique_ptr<KeyFetcher> KeyFetcherGcp::Create(
    google::cloud::kms_v1::v2_25::KeyManagementServiceClient client) {
  return std::make_unique<KeyFetcherGcp>(
      absl::GetFlag(FLAGS_project_id), absl::GetFlag(FLAGS_location_id),
      absl::GetFlag(FLAGS_key_ring_id), absl::GetFlag(FLAGS_private_key_id),
      absl::GetFlag(FLAGS_secret_id), absl::GetFlag(FLAGS_primary_private_key),
      absl::GetFlag(FLAGS_secret), std::move(client));
}

std::unique_ptr<KeyFetcher> KeyFetcher::Create() {
  return std::make_unique<KeyFetcherGcp>(
      absl::GetFlag(FLAGS_project_id), absl::GetFlag(FLAGS_location_id),
      absl::GetFlag(FLAGS_key_ring_id), absl::GetFlag(FLAGS_private_key_id),
      absl::GetFlag(FLAGS_secret_id), absl::GetFlag(FLAGS_primary_private_key),
      absl::GetFlag(FLAGS_secret));
}

}  // namespace privacy_sandbox::key_manager
