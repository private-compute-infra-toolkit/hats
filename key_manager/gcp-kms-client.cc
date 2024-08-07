/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "key_manager/gcp-kms-client.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/status.h"
#include "key_manager/gcp-status.h"

namespace privacy_sandbox::key_manager {

absl::StatusOr<PublicKey> GcpKmsClient::GetPublicKey(absl::string_view key_id) {
  google::cloud::kms::v1::GetPublicKeyRequest request;
  request.set_name(key_id);
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::PublicKey> result =
      client_.GetPublicKey(request);
  if (!result.ok()) {
    return GcpToAbslStatus(result.status());
  }
  PublicKey custom_key;
  custom_key.pem_key = result->pem();
  return custom_key;
}

absl::StatusOr<CryptoKey> GcpKmsClient::CreateAsymmetricKey(
    absl::string_view parent, absl::string_view key_id) {
  google::cloud::kms::v1::CreateCryptoKeyRequest request;
  request.set_parent(parent);
  request.set_crypto_key_id(key_id);

  google::cloud::kms::v1::CryptoKey gcp_key;
  gcp_key.set_purpose(google::cloud::kms::v1::CryptoKey::ASYMMETRIC_SIGN);
  gcp_key.mutable_version_template()->set_algorithm(
      google::cloud::kms::v1::
          CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P256_SHA256);
  *request.mutable_crypto_key() = std::move(gcp_key);
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::CryptoKey> result =
      client_.CreateCryptoKey(request);
  if (!result.ok()) {
    return GcpToAbslStatus(result.status());
  }
  CryptoKey custom_key;
  custom_key.key_id = result->name();
  return custom_key;
}

absl::StatusOr<std::string> GcpKmsClient::EncryptData(
    absl::string_view key_id, absl::string_view plaintext,
    absl::string_view associated_data) {
  google::cloud::kms::v1::EncryptRequest request;
  request.set_name(key_id);
  request.set_plaintext(plaintext);
  request.set_additional_authenticated_data(associated_data);
  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::EncryptResponse>
      result = client_.Encrypt(request);

  if (!result.ok()) {
    return GcpToAbslStatus(result.status());
  }

  return result->ciphertext();
}

absl::StatusOr<std::string> GcpKmsClient::DecryptData(
    absl::string_view key_id, absl::string_view ciphertext,
    absl::string_view associated_data) {
  google::cloud::kms::v1::DecryptRequest request;
  request.set_name(key_id);
  request.set_ciphertext(ciphertext);
  request.set_additional_authenticated_data(associated_data);

  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::DecryptResponse>
      result = client_.Decrypt(request);

  if (!result.ok()) {
    return GcpToAbslStatus(result.status());
  }
  return result->plaintext();
}

GcpKmsClient::GcpKmsClient(
    google::cloud::kms_v1::v2_25::KeyManagementServiceClient client)
    : client_(std::move(client)) {}

}  // namespace privacy_sandbox::key_manager
