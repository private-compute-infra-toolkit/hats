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

#include <utility>

#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/mocks/mock_spanner_connection.h"
#include "google/cloud/spanner/mocks/row.h"
#include "gtest/gtest.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace privacy_sandbox::tvs {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::StrEq;

constexpr absl::string_view kTestAppraisalPolicy = R"pb(
  signed_policy {
    policy {
      oak_containers {
        root_layer {
          amd_sev {
            stage0 { skip {} }
            min_tcb_version { boot_loader: 7 snp: 15 microcode: 62 }
          }
        }
        kernel_layer {
          kernel {
            digests {
              image {
                digests {
                  sha2_256: "D*6\221>.)\235\242\265\026\201D\203\266\254\357\021\266>\003\3675a\003A\250V\0223\367\277"
                }
              }
              setup_data {
                digests {
                  sha2_256: "h\313Bj\372\242\224e\367\307\037&\324\371\253Z\202\302\341\222b6d\213\354\"j\201\224C\035\271"
                }
              }
            }
          }
          init_ram_fs {
            digests {
              digests {
                sha2_256: ";0y=\1778\210t*\326?\023\353\346\240\003\274\233v4\231,dx\246\020\037\236\363#\265\256"
              }
            }
          }
          memory_map {
            digests {
              digests {
                sha2_256: "L\230T(\375\306\020\034q\314&\335\303\023\315\202!\274\274TG\031\221\3549\261\276\002m\016\034("
              }
            }
          }
          acpi {
            digests {
              digests {
                sha2_256: "\244\337\235\212d\334\271\247\023\316\300(\327\r+\025\231\372\357\007\314\320\320\341\201i1IkH\230\310"
              }
            }
          }
          kernel_cmd_line_text {
            string_literals {
              value: " console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off"
            }
          }
        }
        system_layer {
          system_image {
            digests {
              digests {
                sha2_256: "\343\336\331\347\317\331S\264\356cs\373\213A*v\276\020*n\335N\005\252\177\211p\342\013\374K\315"
              }
            }
          }
        }
        container_layer {
          binary {
            digests {
              digests {
                sha2_256: "\277\027=\204ld\345\312\364\221\336\233^\242\337\2544\234\376\"\245\346\360:\330\004\213\270\n\336C\014"
              }
            }
          }
          configuration {
            digests {
              digests {
                sha2_256: "\343\260\304B\230\374\034\024\232\373\364\310\231o\271$\'\256A\344d\233\223L\244\225\231\033xR\270U"
              }
            }
          }
        }
      }
    }
  })pb";

absl::StatusOr<AppraisalPolicies> GetTestAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(kTestAppraisalPolicy,
                                                     &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policies");
  }
  return appraisal_policies;
}

TEST(KeyFetcherGcp, GetLatestNPolicies) {
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

  absl::StatusOr<AppraisalPolicies> expected_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(expected_policies.ok());
  EXPECT_CALL(*mock_result_set_source, NextRow())
      .WillOnce(Return(google::cloud::spanner_mocks::MakeRow(
          {{"Policy",
            google::cloud::spanner::Value(google::cloud::spanner::Bytes(
                expected_policies->signed_policy(0).SerializeAsString()))}})))
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
  constexpr int64_t kN = 5;
  absl::StatusOr<AppraisalPolicies> policies =
      policy_fetcher->GetLatestNPolicies(kN);
  ASSERT_TRUE(policies.ok());
  EXPECT_EQ(policies->SerializeAsString(),
            expected_policies->SerializeAsString());
}

TEST(KeyFetcherGcp, NotFoundError) {
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
  EXPECT_THAT(
      policy_fetcher->GetLatestNPolicies(/*n=*/5),
      StatusIs(absl::StatusCode::kNotFound, HasSubstr("No policies found")));
}

}  // namespace
}  // namespace privacy_sandbox::tvs
