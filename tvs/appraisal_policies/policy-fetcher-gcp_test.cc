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

#include "tvs/appraisal_policies/policy-fetcher-gcp.h"

#include <memory>
#include <string>
#include <utility>

#include <openssl/sha.h>

#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "gmock/gmock.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/mocks/mock_spanner_connection.h"
#include "google/cloud/spanner/mocks/row.h"
#include "gtest/gtest.h"
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_test_macros.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace pcit::tvs {
namespace {

using ::google::protobuf::EqualsProto;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;

constexpr absl::string_view kTestAppraisalPolicies = R"pb(
  policies {
    measurement {
      stage0_measurement {
        amd_sev {
          sha384: "de654ed1eb03b69567338d357f86735c64fc771676bcd5d05ca6afe86f3eb9f7549222afae6139a8d282a34d09d59f95"
          min_tcb_version { boot_loader: 7 snp: 15 microcode: 62 }
        }
      }
      kernel_image_sha256: "442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf"
      kernel_setup_data_sha256: "68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9"
      init_ram_fs_sha256: "3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae"
      memory_map_sha256: "4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28"
      acpi_table_sha256: "a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8"
      kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$"
      system_image_sha256: "e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd"
      container_binary_sha256: "bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c"
    }
    signature {
      signature: "003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c"
      signer: "hats"
    }
  })pb";

absl::StatusOr<AppraisalPolicies> GetTestAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(kTestAppraisalPolicies,
                                                     &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policies");
  }
  return appraisal_policies;
}

#if defined(DYNAMIC_ATTESTATION)
TEST(KeyFetcherGcp, GetLatestNPoliciesSuccessfull_With_Blobs) {
  // create fake blob data
  const std::string kFakeBlobData = "fake_blob_data";
  std::string kFakeBlobShaRaw(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const unsigned char*>(kFakeBlobData.data()),
         kFakeBlobData.size(),
         reinterpret_cast<unsigned char*>(kFakeBlobShaRaw.data()));
  const std::string kFakeBlobShaHex = absl::BytesToHexString(kFakeBlobShaRaw);

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());

  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();
  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields:
      [ {
        name: "PolicyId",
        type: { code: INT64 }
      }
        , {
          name: "Policy",
          type: { code: BYTES }
        }
        , {
          name: "Sha256Digest",
          type: { code: BYTES }
        }
        , {
          name: "BlobData",
          type: { code: BYTES }
        }]
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow({
          {"PolicyId", google::cloud::spanner::Value(123)},
          {"Policy",
           google::cloud::spanner::Value(google::cloud::spanner::Bytes(
               expected_policies.policies(0).SerializeAsString()))},
          {"Sha256Digest", google::cloud::spanner::Value(
                               google::cloud::spanner::Bytes(kFakeBlobShaRaw))},
          {"BlobData", google::cloud::spanner::Value(
                           google::cloud::spanner::Bytes(kFakeBlobData))},
      })))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(Return(google::cloud::spanner::RowStream(
          std::move(mock_result_set_source))));
  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));

  AppraisalPolicies expected_policies_with_blobs = expected_policies;
  (*expected_policies_with_blobs
        .mutable_stage0_binary_sha256_to_blob())[kFakeBlobShaHex] =
      kFakeBlobData;
  std::string expected_text_proto;
  google::protobuf::TextFormat::PrintToString(expected_policies_with_blobs,
                                              &expected_text_proto);
  HATS_EXPECT_OK_AND_HOLDS(policy_fetcher->GetLatestNPolicies(
                               /*n=*/5),
                           EqualsProto(expected_text_proto));
}

TEST(KeyFetcherGcp, GetLatestNPoliciesNotFoundError_With_Blobs) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields:
      [ {
        name: "PolicyId",
        type: { code: INT64 }
      }
        , {
          name: "Policy",
          type: { code: BYTES }
        }
        , {
          name: "Sha256Digest",
          type: { code: BYTES }
        }
        , {
          name: "BlobData",
          type: { code: BYTES }
        }]
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(Return(google::cloud::spanner::RowStream(
          std::move(mock_result_set_source))));
  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPolicies(/*n=*/5),
                             absl::StatusCode::kNotFound,
                             HasSubstr("No policies found"));
}

TEST(KeyFetcherGcp, GetLatestNPoliciesForDigest_With_Blobs) {
  // create fake blob data
  const std::string kFakeBlobData = "fake_blob_data";
  std::string kFakeBlobShaRaw(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const unsigned char*>(kFakeBlobData.data()),
         kFakeBlobData.size(),
         reinterpret_cast<unsigned char*>(kFakeBlobShaRaw.data()));
  const std::string kFakeBlobShaHex = absl::BytesToHexString(kFakeBlobShaRaw);

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());

  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields:
      [ {
        name: "PolicyId",
        type: { code: INT64 }
      }
        , {
          name: "Policy",
          type: { code: BYTES }
        }
        , {
          name: "Sha256Digest",
          type: { code: BYTES }
        }
        , {
          name: "BlobData",
          type: { code: BYTES }
        }]
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow({
          {"PolicyId", google::cloud::spanner::Value(123)},
          {"Policy",
           google::cloud::spanner::Value(google::cloud::spanner::Bytes(
               expected_policies.policies(0).SerializeAsString()))},
          {"Sha256Digest", google::cloud::spanner::Value(
                               google::cloud::spanner::Bytes(kFakeBlobShaRaw))},
          {"BlobData", google::cloud::spanner::Value(
                           google::cloud::spanner::Bytes(kFakeBlobData))},
      })))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  constexpr absl::string_view kApplicationDigest = "some_digest";
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source, &kApplicationDigest](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            // Make sure the right parameter is specified in the code.
            google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
                sql_params.statement.GetParameter("application_digest");
            if (!parameter.ok()) return {};
            google::cloud::StatusOr<google::cloud::spanner::Bytes>
                application_digest =
                    parameter->get<google::cloud::spanner::Bytes>();
            if (!application_digest.ok()) return {};
            if (application_digest->get<std::string>() != kApplicationDigest) {
              return {};
            }
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });
  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));

  AppraisalPolicies expected_policies_with_blobs = expected_policies;
  (*expected_policies_with_blobs
        .mutable_stage0_binary_sha256_to_blob())[kFakeBlobShaHex] =
      kFakeBlobData;
  std::string expected_text_proto;
  google::protobuf::TextFormat::PrintToString(expected_policies_with_blobs,
                                              &expected_text_proto);
  HATS_EXPECT_OK_AND_HOLDS(
      policy_fetcher->GetLatestNPoliciesForDigest(kApplicationDigest,
                                                  /*n=*/5),
      EqualsProto(expected_text_proto));
}

TEST(KeyFetcherGcp, GetLatestNPoliciesForDigestNotFoundError_With_Blobs) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields:
      [ {
        name: "PolicyId",
        type: { code: INT64 }
      }
        , {
          name: "Policy",
          type: { code: BYTES }
        }
        , {
          name: "Sha256Digest",
          type: { code: BYTES }
        }
        , {
          name: "BlobData",
          type: { code: BYTES }
        }]
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(Return(google::cloud::spanner::RowStream(
          std::move(mock_result_set_source))));
  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPoliciesForDigest(
                                 /*application_digest=*/"some_digest", /*n=*/5),
                             absl::StatusCode::kNotFound,
                             HasSubstr("No policies found"));
}

#else
TEST(KeyFetcherGcp, GetLatestNPoliciesSuccessfull) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Policy"
        type: { code: BYTES }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());
  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Policy",
            google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                expected_policies.policies(0).SerializeAsString()))}})))
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
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));

  HATS_EXPECT_OK_AND_HOLDS(policy_fetcher->GetLatestNPolicies(
                               /*n=*/5),
                           EqualsProto(kTestAppraisalPolicies));
}

TEST(KeyFetcherGcp, GetLatestNPoliciesNotFoundError) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Policy"
        type: { code: BYTES }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
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
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPolicies(/*n=*/5),
                             absl::StatusCode::kNotFound,
                             HasSubstr("No policies found"));
}

TEST(KeyFetcherGcp, GetLatestNPoliciesForDigest) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Policy"
        type: { code: BYTES }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());
  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Policy",
            google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                expected_policies.policies(0).SerializeAsString()))}})))
      .WillOnce(Return(google::cloud::spanner::Row()));

  auto mock_connection =
      std::make_shared<google::cloud::spanner_mocks::MockConnection>();

  constexpr absl::string_view kApplicationDigest = "some_digest";
  EXPECT_CALL(*mock_connection, ExecuteQuery)
      .WillOnce(
          [&mock_result_set_source, &kApplicationDigest](
              const google::cloud::spanner::Connection::SqlParams& sql_params)
              -> google::cloud::spanner::RowStream {
            // Make sure the right parameter is specified in the code.
            google::cloud::StatusOr<google::cloud::spanner::Value> parameter =
                sql_params.statement.GetParameter("application_digest");
            if (!parameter.ok()) return {};
            google::cloud::StatusOr<google::cloud::spanner::Bytes>
                application_digest =
                    parameter->get<google::cloud::spanner::Bytes>();
            if (!application_digest.ok()) return {};
            if (application_digest->get<std::string>() != kApplicationDigest) {
              return {};
            }
            return google::cloud::spanner::RowStream(
                std::move(mock_result_set_source));
          });
  google::cloud::spanner::Client spanner_client(mock_connection);
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));

  HATS_EXPECT_OK_AND_HOLDS(
      policy_fetcher->GetLatestNPoliciesForDigest(kApplicationDigest,
                                                  /*n=*/5),
      EqualsProto(kTestAppraisalPolicies));
}

TEST(KeyFetcherGcp, GetLatestNPoliciesForDigestNotFoundError) {
  auto mock_result_set_source =
      std::make_unique<google::cloud::spanner_mocks::MockResultSetSource>();

  constexpr absl::string_view kSchema = R"pb(
    row_type: {
      fields: {
        name: "Policy"
        type: { code: BYTES }
      }
    })pb";
  google::spanner::v1::ResultSetMetadata metadata;
  ASSERT_TRUE(
      google::protobuf::TextFormat::ParseFromString(kSchema, &metadata));
  EXPECT_CALL(*mock_result_set_source, Metadata())
      .WillRepeatedly(Return(metadata));

  EXPECT_CALL(*mock_result_set_source, NextRow())
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
  std::unique_ptr<PolicyFetcher> policy_fetcher =
      PolicyFetcherGcp::Create(std::move(spanner_client));
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPoliciesForDigest(
                                 /*application_digest=*/"some_digest", /*n=*/5),
                             absl::StatusCode::kNotFound,
                             HasSubstr("No policies found"));
}
#endif  // defined(DYNAMIC_ATTESTATION)

}  // namespace
}  // namespace pcit::tvs
