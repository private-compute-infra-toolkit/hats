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

#include <utility>

#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "gmock/gmock.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/key_management_connection.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/mocks/mock_spanner_connection.h"
#include "google/cloud/spanner/mocks/row.h"
#include "gtest/gtest.h"

namespace privacy_sandbox::key_manager {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;

// Emulate KMS service connection. The class takes an encryption key and
// expected name (KMS resource name) and ciphertext. If the request matches the
// name and ciphertext, the encryption key is returned; otherwise and error is
// returned.
class TestKeyManagementServiceConnection
    : public google::cloud::kms_v1::v2_25::KeyManagementServiceConnection {
 public:
  TestKeyManagementServiceConnection(absl::string_view expected_resource_name,
                                     absl::string_view expected_ciphertext,
                                     crypto::SecretData& dek)
      : expected_resource_name_(expected_resource_name),
        expected_ciphertext_(expected_ciphertext),
        dek_(dek) {}

  google::cloud::v2_25::StatusOr<google::cloud::kms::v1::DecryptResponse>
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
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "PrivateKey",
        type: { code: BYTES }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data1");
  absl::StatusOr<std::string> encrypted_data =
      crypto::Encrypt(dek, data, crypto::kTvsPrivateKeyAd);
  ASSERT_TRUE(encrypted_data.ok());

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"PrivateKey", google::cloud::spanner::Value(
                              google::cloud::spanner::Bytes(*encrypted_data))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))}})));

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
  EXPECT_THAT(key_fetcher->GetPrimaryPrivateKey(),
              IsOkAndHolds(StrEq("data1")));
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
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "PrivateKey",
        type: { code: BYTES }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data2");
  absl::StatusOr<std::string> encrypted_data =
      crypto::Encrypt(dek, data, crypto::kTvsPrivateKeyAd);
  ASSERT_TRUE(encrypted_data.ok());

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"PrivateKey", google::cloud::spanner::Value(
                              google::cloud::spanner::Bytes(*encrypted_data))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))}})));

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
  EXPECT_THAT(key_fetcher->GetSecondaryPrivateKey(),
              IsOkAndHolds(StrEq("data2")));
}

// This test generates a DEK, pass it to the test KMS to return it to the
// KeyFetcher. Encrypt some data with the DEK and have mock spanner return it.
// The key fetcher should be able to decrypt the encrypted data.
TEST(KeyFetcherGcp, GetSecret) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secret";
  constexpr absl::string_view kCiphertext = "test_dek_secret";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  absl::StatusOr<std::string> encrypted_data =
      crypto::Encrypt(dek, data, crypto::kSecretAd);
  ASSERT_TRUE(encrypted_data.ok());

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(*encrypted_data))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))}})));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  constexpr absl::string_view kUserName = "test_secret";
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source, kUserName](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            // Make sure the right parameter is specified in the code.
            google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
                sql_params.statement.GetParameter("username");
            if (!parameter.ok()) return {};
            google::cloud::StatusOr<std::string> user_name =
                parameter->get<std::string>();
            if (!user_name.ok()) return {};
            if (*user_name != kUserName) return {};
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<KeyFetcher> key_fetcher =
      KeyFetcherGcp::Create(std::move(test_client), std::move(spanner_client));

  // The actual test.
  EXPECT_THAT(key_fetcher->GetSecret(kUserName), IsOkAndHolds(StrEq("data3")));
}

TEST(KeyFetcherGcp, UserIdForAuthenticationKey) {
  crypto::SecretData dek(5);
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      /*expected_resource_name=*/"", /*expected_ciphertext=*/"", dek);
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
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
  EXPECT_THAT(key_fetcher->UserIdForAuthenticationKey(kPublicKey),
              IsOkAndHolds(Eq(kUserId)));
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
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  absl::StatusOr<std::string> encrypted_data =
      crypto::Encrypt(dek, data, crypto::kSecretAd);
  ASSERT_TRUE(encrypted_data.ok());

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(*encrypted_data))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))}})));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  constexpr int64_t kUserId = 1234;
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce([&mock_result_set_source, &kUserId](
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
  EXPECT_THAT(key_fetcher->GetSecretForUserId(kUserId),
              IsOkAndHolds(StrEq("data3")));
}

TEST(KeyFetcherGcp, KMSError) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secret";
  constexpr absl::string_view kCiphertext = "test_dek_secret";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  absl::StatusOr<std::string> encrypted_data =
      crypto::Encrypt(dek, data, crypto::kSecretAd);
  ASSERT_TRUE(encrypted_data.ok());

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(*encrypted_data))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"ResourceName", google::cloud::spanner::Value("")}})));

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
  EXPECT_THAT(key_fetcher->GetSecret(/*username=*/""),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("TestKeyManagementServiceConnection failed")));
}

TEST(KeyFetcherGcp, DecryptionError) {
  crypto::SecretData dek = crypto::RandomAeadKey();
  constexpr absl::string_view kResourceName = "test_kek_secret";
  constexpr absl::string_view kCiphertext = "test_dek_secret";
  auto test_connection = std::make_shared<TestKeyManagementServiceConnection>(
      kResourceName, kCiphertext, dek);
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient test_client(
      test_connection);
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Secret",
        type: { code: BYTES }
      }
      fields: {
        name: "Dek",
        type: { code: BYTES }
      }
      fields: {
        name: "ResourceName",
        type: { code: STRING }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  crypto::SecretData data("data3");
  absl::StatusOr<std::string> encrypted_data =
      crypto::Encrypt(dek, data, crypto::kTvsPrivateKeyAd);
  ASSERT_TRUE(encrypted_data.ok());

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Secret", google::cloud::spanner::Value(
                          google::cloud::spanner::Bytes(*encrypted_data))},
           {"Dek", google::cloud::spanner::Value(
                       google::cloud::spanner::Bytes((kCiphertext)))},
           {"ResourceName",
            google::cloud::spanner::Value(std::string(kResourceName))}})));

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
  EXPECT_THAT(key_fetcher->GetSecret(/*username=*/""),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("EVP_AEAD_CTX_open failed")));
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
