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

#include "gcp-kms-client.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "gtest/gtest.h"
#include "key_manager/kms-client.h"

namespace privacy_sandbox::key_manager {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::testing::_;
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;

constexpr absl::string_view kExpectedKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1";
constexpr absl::string_view kExpectedParent =
    "projects/P1/locations/L1/keyRings/R1";
constexpr absl::string_view kExpectedPlaintext = "Sensitive data to encrypt";
constexpr absl::string_view kExpectedCiphertext = "Encrypted data here";

TEST(GcpKmsClientTest, GetPublicKeySuccess) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);
  google::cloud::kms::v1::PublicKey expected_public_key;
  expected_public_key.set_pem("pem");
  EXPECT_CALL(*mock_connection, GetPublicKey)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::PublicKey>(expected_public_key)));

  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  EXPECT_THAT(client->GetPublicKey(kExpectedKeyName),
              IsOkAndHolds(AllOf(
                  Field(&PublicKey::pem_key, expected_public_key.pem()))));
}

TEST(GcpKmsClientTest, GetPublicKeyFailure) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);
  google::cloud::Status error_status(
      google::cloud::StatusCode::kPermissionDenied, "Permission denied");
  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  EXPECT_CALL(*mock_connection, GetPublicKey)
      .WillOnce(
          Return(StatusOr<google::cloud::kms::v1::PublicKey>(error_status)));
  EXPECT_THAT(client->GetPublicKey(kExpectedKeyName),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(GcpKmsClientTest, CreateAsymmetricKeySuccess) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);
  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  google::cloud::kms::v1::CryptoKey expected_crypto_key;
  expected_crypto_key.set_name("key-name");
  EXPECT_CALL(*mock_connection, CreateCryptoKey)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::CryptoKey>(expected_crypto_key)));

  absl::StatusOr<privacy_sandbox::key_manager::CryptoKey> actual_crypto_key =
      client->CreateAsymmetricKey(kExpectedParent, kExpectedKeyName);
  EXPECT_THAT(actual_crypto_key.value(),
              AllOf(Field(&privacy_sandbox::key_manager::CryptoKey::key_id,
                          "key-name")));
}

TEST(GcpKmsClientTest, CreateAsymmetricKeyFailure) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);
  google::cloud::Status error_status(
      google::cloud::StatusCode::kPermissionDenied, "Permission denied");
  EXPECT_CALL(*mock_connection, CreateCryptoKey)
      .WillOnce(
          Return(StatusOr<google::cloud::kms::v1::CryptoKey>(error_status)));

  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  google::cloud::kms::v1::CryptoKey expected_crypto_key;
  EXPECT_THAT(client->CreateAsymmetricKey(kExpectedParent, kExpectedKeyName),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(GcpKmsClientTest, EncryptDataSuccess) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);

  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));

  constexpr absl::string_view kKeyId = "test_key_id1";
  constexpr absl::string_view kPlaintext = "test_plaintext1";
  constexpr absl::string_view kAssociatedData = "test_ad1";
  EXPECT_CALL(*mock_connection, Encrypt)
      .WillOnce([&](const google::cloud::kms::v1::EncryptRequest& request)
                    -> google::cloud::StatusOr<
                        google::cloud::kms::v1::EncryptResponse> {
        // Return a valid result if and only if the request sent by GcpKmsClient
        // matches the request we expect to be sent based on the arguments
        // passed to `EncryptData()`.
        if (request.name() == kKeyId && request.plaintext() == kPlaintext &&
            request.additional_authenticated_data() == kAssociatedData) {
          google::cloud::kms::v1::EncryptResponse response;
          response.set_ciphertext(kExpectedCiphertext);
          return response;
        }
        return google::cloud::Status(
            google::cloud::StatusCode::kInvalidArgument, "Invalid request.");
      });

  EXPECT_THAT(client->EncryptData(kKeyId, kPlaintext, kAssociatedData),
              IsOkAndHolds(kExpectedCiphertext));
}

TEST(GcpKmsClientTest, EncryptDataFailure_InvalidRequest) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);

  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  google::cloud::Status error_status(
      google::cloud::StatusCode::kInvalidArgument, "Invalid request");

  EXPECT_CALL(*mock_connection, Encrypt)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::EncryptResponse>(error_status)));

  EXPECT_THAT(client->EncryptData(kExpectedKeyName, kExpectedPlaintext,
                                  "associated_data"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(GcpKmsClientTest, DecryptDataSuccess) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);

  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  google::cloud::kms::v1::DecryptResponse expected_response;
  expected_response.set_plaintext(kExpectedPlaintext);

  constexpr absl::string_view kKeyId = "test_key_id2";
  constexpr absl::string_view kCiphertext = "secret_text2";
  constexpr absl::string_view kAssociatedData = "test_ad2";
  EXPECT_CALL(*mock_connection, Decrypt)
      .WillOnce([&](const google::cloud::kms::v1::DecryptRequest& request)
                    -> google::cloud::StatusOr<
                        google::cloud::kms::v1::DecryptResponse> {
        // Return a valid result if and only if the request sent by GcpKmsClient
        // matches the request we expect to be sent based on the arguments
        // passed to `DecryptData()`.
        if (request.name() == kKeyId && request.ciphertext() == kCiphertext &&
            request.additional_authenticated_data() == kAssociatedData) {
          google::cloud::kms::v1::DecryptResponse response;
          response.set_plaintext(kExpectedPlaintext);
          return response;
        }
        return google::cloud::Status(
            google::cloud::StatusCode::kInvalidArgument, "Invalid request.");
      });

  EXPECT_THAT(client->DecryptData(kKeyId, kCiphertext, kAssociatedData),
              IsOkAndHolds(kExpectedPlaintext));
}

TEST(GcpKmsClientTest, DecryptDataFailure_AuthenticationError) {
  auto mock_connection = std::make_shared<
      google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient mock_client(
      mock_connection);

  std::unique_ptr<GcpKmsClient> client =
      std::make_unique<GcpKmsClient>(std::move(mock_client));
  google::cloud::Status error_status(
      google::cloud::StatusCode::kPermissionDenied, "Permission denied");
  EXPECT_CALL(*mock_connection, Decrypt)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::DecryptResponse>(error_status)));

  EXPECT_THAT(client->DecryptData(kExpectedKeyName, kExpectedCiphertext,
                                  "associated_data"),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace privacy_sandbox::key_manager
