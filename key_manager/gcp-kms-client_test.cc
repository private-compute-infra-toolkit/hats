#include "key_manager/gcp-kms-client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fstream>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/key_management_connection.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/client_context.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
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
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::kms::v1::PublicKey expected_public_key;
  expected_public_key.set_pem("pem");
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::PublicKey>(expected_public_key)));
  EXPECT_THAT(client_->GetPublicKey(std::string(kExpectedKeyName)),
              IsOkAndHolds(AllOf(
                  Field(&PublicKey::pem_key, expected_public_key.pem()))));
}

TEST(GcpKmsClientTest, GetPublicKeyFailure) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);
  google::cloud::Status error_status(
      google::cloud::StatusCode::kPermissionDenied, "Permission denied");
  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce(
          Return(StatusOr<google::cloud::kms::v1::PublicKey>(error_status)));

  EXPECT_THAT(client_->GetPublicKey(std::string(kExpectedKeyName)),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(GcpKmsClientTest, CreateAsymmetricKeySuccess) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::kms::v1::CryptoKey expected_crypto_key;
  expected_crypto_key.set_name("key-name");
  EXPECT_CALL(*mock_connection_, CreateCryptoKey)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::CryptoKey>(expected_crypto_key)));
  absl::StatusOr<privacy_sandbox::key_manager::CryptoKey> actual_crypto_key =
      client_->CreateAsymmetricKey(std::string(kExpectedParent),
                                   std::string(kExpectedKeyName));
  EXPECT_THAT(actual_crypto_key.value(),
              AllOf(Field(&privacy_sandbox::key_manager::CryptoKey::key_id,
                          "key-name")));
}

TEST(GcpKmsClientTest, CreateAsymmetricKeyFailure) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::kms::v1::CryptoKey expected_crypto_key;
  google::cloud::Status error_status(
      google::cloud::StatusCode::kPermissionDenied, "Permission denied");

  EXPECT_CALL(*mock_connection_, CreateCryptoKey)
      .WillOnce(
          Return(StatusOr<google::cloud::kms::v1::CryptoKey>(error_status)));

  absl::StatusOr<privacy_sandbox::key_manager::CryptoKey> actual_crypto_key =
      client_->CreateAsymmetricKey(std::string(kExpectedParent),
                                   std::string(kExpectedKeyName));

  EXPECT_THAT(actual_crypto_key, StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(GcpKmsClientTest, EncryptDataSuccess) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::kms::v1::EncryptResponse expected_response;
  expected_response.set_ciphertext(std::string(kExpectedCiphertext));

  EXPECT_CALL(*mock_connection_, Encrypt)
      .WillOnce(Return(StatusOr<google::cloud::kms::v1::EncryptResponse>(
          expected_response)));

  absl::StatusOr<std::string> encrypt_response = client_->EncryptData(
      std::string(kExpectedKeyName), std::string(kExpectedPlaintext));
  EXPECT_THAT(encrypt_response.value(), "Encrypted data here");
}

TEST(GcpKmsClientTest, EncryptDataFailure_InvalidRequest) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::Status error_status(
      google::cloud::StatusCode::kInvalidArgument, "Invalid request");

  EXPECT_CALL(*mock_connection_, Encrypt)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::EncryptResponse>(error_status)));

  absl::StatusOr<std::string> encrypt_response = client_->EncryptData(
      std::string(kExpectedKeyName), std::string(kExpectedPlaintext));

  EXPECT_THAT(encrypt_response, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(GcpKmsClientTest, DecryptDataSuccess) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::kms::v1::DecryptResponse expected_response;
  expected_response.set_plaintext(std::string(kExpectedPlaintext));

  EXPECT_CALL(*mock_connection_, Decrypt)
      .WillOnce(Return(StatusOr<google::cloud::kms::v1::DecryptResponse>(
          expected_response)));

  absl::StatusOr<std::string> decrypt_response = client_->DecryptData(
      std::string(kExpectedKeyName), std::string(kExpectedCiphertext));

  EXPECT_THAT(decrypt_response.value(), kExpectedPlaintext);
}

TEST(GcpKmsClientTest, DecryptDataFailure_AuthenticationError) {
  std::shared_ptr<
      ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>
      mock_connection_ = std::make_shared<
          ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection>();
  std::shared_ptr<::google::cloud::kms_v1::KeyManagementServiceClient>
      mock_client_ =
          std::make_shared<::google::cloud::kms_v1::KeyManagementServiceClient>(
              mock_connection_);

  std::unique_ptr<GcpKmsClient> client_ =
      std::make_unique<GcpKmsClient>(mock_client_);
  google::cloud::Status error_status(
      google::cloud::StatusCode::kPermissionDenied, "Permission denied");

  EXPECT_CALL(*mock_connection_, Decrypt)
      .WillOnce(Return(
          StatusOr<google::cloud::kms::v1::DecryptResponse>(error_status)));

  absl::StatusOr<std::string> decrypt_response = client_->DecryptData(
      std::string(kExpectedKeyName), std::string(kExpectedCiphertext));

  EXPECT_THAT(decrypt_response, StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace privacy_sandbox::key_manager