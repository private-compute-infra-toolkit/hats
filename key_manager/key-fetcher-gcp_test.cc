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
#include <utility>

#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "gmock/gmock.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/key_management_connection.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/mocks/mock_spanner_connection.h"
#include "google/cloud/spanner/mocks/row.h"
#include "gtest/gtest.h"
#include "status_macro/status_test_macros.h"

namespace privacy_sandbox::key_manager {
namespace {

using ::testing::Eq;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

// Emulate KMS service connection. The class takes an encryption key and
// expected name (KMS resource name) and ciphertext. If the request matches the
// name and ciphertext, the encryption key is returned; otherwise and error is
// returned.
class TestKeyManagementServiceConnection
    : public google::cloud::kms_v1::v2_29::KeyManagementServiceConnection {
 public:
  TestKeyManagementServiceConnection(absl::string_view expected_resource_name,
                                     absl::string_view expected_ciphertext,
                                     crypto::SecretData& dek)
      : expected_resource_name_(expected_resource_name),
        expected_ciphertext_(expected_ciphertext),
        dek_(dek) {}

  google::cloud::v2_29::StatusOr<google::cloud::kms::v1::DecryptResponse>
  Decrypt(const google::cloud::kms::v1::DecryptRequest& request) override {
    google::cloud::kms::v1::DecryptResponse response;
    if (request.name() == expected_resource_name_ &&
        absl::StrContains(request.ciphertext(), expected_ciphertext_)) {
      response.set_plaintext(dek_.GetStringView());
    } else {
      return google::cloud::Status(google::cloud::StatusCode::kInternal,
                                   "TestKeyManagementServiceConnection failed");
    }
    return response;
  }

 private:
  std::string expected_resource_name_;
  std::string expected_ciphertext_;
  crypto::SecretData dek_;
};

// This test generates a DEK, pass it to the test KMS to return it to the
// KeyFetcher. Encrypt some data with the DEK and have mock spanner return it.
// The key fetcher should be able to decrypt the encrypted data.
TEST(KeyFetcherGcp, GetPrimaryPrivateKey) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_primary";
  constexpr absl::string_view kCiphertext = "test_dek_primary";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "PrivateKey",
        type: { code: BYTES }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data1");
  HATS_ASSERT_OK_AND_ASSIGN(
      std::string encrypted_data,
      crypto::Encrypt(dek, data, crypto::kTvsPrivateKeyAd));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"PrivateKey",
            google::cloud::spanner::Value(
                google::cloud::spanner::Bytes(encrypted_data))}})));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            // Make sure the right parameter is specified in the code.
            google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
                sql_params.statement.GetParameter("key_name");
            if (!parameter.ok()) return {};
            google::cloud::StatusOr<std::string> key_name =
                parameter->get<std::string>();
            if (!key_name.ok()) return {};
            if (*key_name != "primary_key") return {};
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetPrimaryPrivateKey(), StrEq("data1"));
}

// This test generates a DEK, pass it to the test KMS to return it to the
// KeyFetcher. Encrypt some data with the DEK and have mock spanner return it.
// The key fetcher should be able to decrypt the encrypted data.
TEST(KeyFetcherGcp, GetSecondaryPrimaryKey) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secondary";
  constexpr absl::string_view kCiphertext = "test_dek_secondary";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "PrivateKey",
        type: { code: BYTES }
      }
    })pb";

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data2");
  HATS_ASSERT_OK_AND_ASSIGN(
      std::string encrypted_data,
      crypto::Encrypt(dek, data, crypto::kTvsPrivateKeyAd));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"PrivateKey",
            google::cloud::spanner::Value(
                google::cloud::spanner::Bytes(encrypted_data))}})));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            // Make sure the right parameter is specified in the code.
            google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
                sql_params.statement.GetParameter("key_name");
            if (!parameter.ok()) return {};
            google::cloud::StatusOr<std::string> key_name =
                parameter->get<std::string>();
            if (!key_name.ok()) return {};
            if (*key_name != "secondary_key") return {};
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  HATS_EXPECT_OK_AND_HOLDS(key_fetcher->GetSecondaryPrivateKey(),
                           StrEq("data2"));
}

TEST(KeyFetcherGcp, UserIdForAuthenticationKey) {
  crypto::SecretData dek(5);
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      /*expected_resource_name=*/"", /*expected_ciphertext=*/"", dek);
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "UserId",
        type: { code: INT64 }
      }
    })pb";

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  constexpr int64_t kUserId = 104;
  constexpr absl::string_view kPublicKey = "test_public_key";
  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"UserId", google::cloud::spanner::Value(kUserId)}})));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source, &kPublicKey](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            // Make sure the right parameter is specified in the code.
            google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
                sql_params.statement.GetParameter("public_key");
            if (!parameter.ok()) return {};
            google::cloud::StatusOr<google::cloud::spanner::Bytes> public_key =
                parameter->get<google::cloud::spanner::Bytes>();
            if (!public_key.ok()) return {};
            if (public_key->get<std::string>() != kPublicKey) return {};
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  HATS_EXPECT_OK_AND_HOLDS(key_fetcher->UserIdForAuthenticationKey(kPublicKey),
                           Eq(kUserId));
}

// This test generates a DEK, pass it to the test KMS to return it to the
// KeyFetcher. Encrypt some data with the DEK and have mock spanner return it.
// The key fetcher should be able to decrypt the encrypted data.
TEST(KeyFetcherGcp, GetSecretForUserId) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secret";
  constexpr absl::string_view kCiphertext = "test_dek_secret";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "SecretId",
        type: { code: INT64 }
      }
      fields: {
        name: "PublicKey",
        type: { code: STRING }
      }
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
    })pb";

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data,
                            crypto::Encrypt(dek, data, crypto::kSecretAd));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"SecretId", google::cloud::spanner::Value(3)},
           {"PublicKey", google::cloud::spanner::Value("data3-public")},
           {"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(encrypted_data))}})))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  constexpr int64_t kUserId = 1234;
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce([&mock_result_set_source](
                    const google::cloud::spanner::Connection::SqlParams&
                        sql_params) -> google::cloud::spanner::RowStream {
        // Make sure the right parameter is specified in the code.
        google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
            sql_params.statement.GetParameter("user_id");
        if (!parameter.ok()) return {};
        google::cloud::StatusOr<int64_t> user_id = parameter->get<int64_t>();
        if (!user_id.ok()) return {};
        if (*user_id != kUserId) return {};
        return google::cloud::spanner::RowStream(
            std::move(mock_result_set_source));
      });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  HATS_EXPECT_OK_AND_HOLDS(
      key_fetcher->GetSecretsForUserId(kUserId),
      UnorderedElementsAre(FieldsAre(3, "data3-public", "data3")));
}

TEST(KeyFetcherGcp, KmsError) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secret";
  constexpr absl::string_view kCiphertext = "test_dek_secret";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "SecretId",
        type: { code: INT64 }
      }
      fields: {
        name: "PublicKey",
        type: { code: STRING }
      }
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
    })pb";

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  HATS_ASSERT_OK_AND_ASSIGN(std::string encrypted_data,
                            crypto::Encrypt(dek, data, crypto::kSecretAd));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"ResourceName", google::cloud::spanner::Value("")},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"SecretId", google::cloud::spanner::Value(3)},
           {"PublicKey", google::cloud::spanner::Value("data3-public")},
           {"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(encrypted_data))}})))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce([&mock_result_set_source](
                    const google::cloud::spanner::Connection::SqlParams&)
                    -> google::cloud::spanner::RowStream {
        return google::cloud::spanner::RowStream(
            std::move(mock_result_set_source));
      });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  HATS_EXPECT_STATUS_MESSAGE(
      key_fetcher->GetSecretsForUserId(/*user_id*/ 1234),
      absl::StatusCode::kInternal,
      HasSubstr("TestKeyManagementServiceConnection failed"));
}

TEST(KeyFetcherGcp, DecryptionError) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secret";
  constexpr absl::string_view kCiphertext = "test_dek_secret";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_29::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "SecretId",
        type: { code: INT64 }
      }
      fields: {
        name: "PublicKey",
        type: { code: STRING }
      }
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
    })pb";

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  HATS_ASSERT_OK_AND_ASSIGN(
      std::string encrypted_data,
      crypto::Encrypt(dek, data, crypto::kTvsPrivateKeyAd));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"SecretId", google::cloud::spanner::Value(3)},
           {"PublicKey", google::cloud::spanner::Value("data3-public")},
           {"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(encrypted_data))}})))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce([&mock_result_set_source](
                    const google::cloud::spanner::Connection::SqlParams&)
                    -> google::cloud::spanner::RowStream {
        return google::cloud::spanner::RowStream(
            std::move(mock_result_set_source));
      });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  HATS_EXPECT_STATUS_MESSAGE(key_fetcher->GetSecretsForUserId(/*user_id*/ 1234),
                             absl::StatusCode::kFailedPrecondition,
                             HasSubstr("EVP_AEAD_CTX_open failed"));
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
