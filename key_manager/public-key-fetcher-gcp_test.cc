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

#include "key_manager/public-key-fetcher-gcp.h"

#include <utility>

#include "gmock/gmock.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/mocks/mock_spanner_connection.h"
#include "google/cloud/spanner/mocks/row.h"
#include "google/cloud/status.h"
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

constexpr absl::string_view kGetLatestPublicKeysRowSchema = R"pb(
  row_type: {
    fields: {
      name: "SecretId",
      type: { code: INT64 }
    }
    fields: {
      name: "PublicKey",
      type: { code: STRING }
    }
    fields: {
      name: "Origin",
      type: { code: STRING }
    }
  })pb";
// This test generates a DEK, pass it to the test KMS to return it to the
// KeyFetcher. Encrypt some data with the DEK and have mock spanner return it.
// The key fetcher should be able to decrypt the encrypted data.
TEST(PublicKeyFetcherGcp, GetLatestPublicKeys) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kGetLatestPublicKeysRowSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  // Test will take only one key for each origin. This happens when we have
  // exactly same update timestamp for some origin.
  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow({
          {"SecretId", google::cloud::spanner::Value(4)},
          {"PublicKey", google::cloud::spanner::Value("data4-public")},
          {"Origin", google::cloud::spanner::Value("origin")},
      })))
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow({
          {"SecretId", google::cloud::spanner::Value(2)},
          {"PublicKey", google::cloud::spanner::Value("data2-public")},
          {"Origin", google::cloud::spanner::Value("origin2")},
      })))
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow({
          {"SecretId", google::cloud::spanner::Value(3)},
          {"PublicKey", google::cloud::spanner::Value("data3-public")},
          {"Origin", google::cloud::spanner::Value("origin")},
      })))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PublicKeyFetcher> key_fetcher =
      PublicKeyFetcherGcp::Create(std::move(spanner_client));

  HATS_EXPECT_OK_AND_HOLDS(
      key_fetcher->GetLatestPublicKeys(),
      UnorderedElementsAre(
          FieldsAre(
              /*key_id=*/4, /*public_key=*/"data4-public", /*origin=*/"origin"),
          FieldsAre(
              /*key_id=*/2, /*public_key=*/"data2-public",
              /*origin=*/"origin2")));
}

TEST(PublicKeyFetcherGcp, Failure) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kGetLatestPublicKeysRowSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::Status(
          google::cloud::StatusCode::kUnknown, "unknown error")));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });

  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PublicKeyFetcher> key_fetcher =
      PublicKeyFetcherGcp::Create(std::move(spanner_client));

  HATS_EXPECT_STATUS_MESSAGE(key_fetcher->GetLatestPublicKeys(),
                             absl::StatusCode::kUnknown, HasSubstr("unknown"));
}

}  // namespace

}  // namespace privacy_sandbox::key_manager
