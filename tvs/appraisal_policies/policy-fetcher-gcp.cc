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
#include <tuple>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gcp_common/flags.h"
#include "gcp_common/gcp-status.h"
#include "google/cloud/spanner/client.h"
#include "proto/attestation/reference_value.pb.h"

namespace privacy_sandbox::tvs {

PolicyFetcherGcp::PolicyFetcherGcp(
    google::cloud::spanner::Client spanner_client)
    : spanner_client_(std::move(spanner_client)) {}

PolicyFetcherGcp::PolicyFetcherGcp(absl::string_view project_id,
                                   absl::string_view instance_id,
                                   absl::string_view database_id)
    : spanner_client_(google::cloud::spanner::MakeConnection(
          google::cloud::spanner::Database(std::string(project_id),
                                           std::string(instance_id),
                                           std::string(database_id)))) {}

absl::StatusOr<oak::attestation::v1::ReferenceValues>
PolicyFetcherGcp::GetPolicy(absl::string_view policy_id) {
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          Policy
      FROM
          AppraisalPolicies
      WHERE
          PolicyId = @policy_id)sql",
      {{"policy_id", google::cloud::spanner::Value(std::string(policy_id))}});
  using RowType = std::tuple<google::cloud::spanner::Bytes>;
  auto rows = spanner_client_.ExecuteQuery(std::move(select));
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    if (!row.ok()) {
      return gcp_common::GcpToAbslStatus(row.status());
    }
    oak::attestation::v1::ReferenceValues appraisal_policy;
    if (!appraisal_policy.ParseFromString(
            std::get<0>(*row).get<std::string>())) {
      return absl::FailedPreconditionError(
          absl::StrCat("Failed to parse: '", policy_id, "'"));
    }
    return appraisal_policy;
  }
  return absl::NotFoundError(absl::StrCat("Cannot find '", policy_id, "'"));
}

std::unique_ptr<PolicyFetcher> PolicyFetcherGcp::Create(
    google::cloud::spanner::Client spanner_client) {
  // The constructor is private so we use WrapUnique.
  return absl::WrapUnique(new PolicyFetcherGcp(std::move(spanner_client)));
}

absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create() {
  return std::make_unique<PolicyFetcherGcp>(absl::GetFlag(FLAGS_project_id),
                                            absl::GetFlag(FLAGS_instance_id),
                                            absl::GetFlag(FLAGS_database_id));
}

}  // namespace privacy_sandbox::tvs
