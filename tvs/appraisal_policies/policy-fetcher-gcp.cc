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
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/sql_statement.h"
#include "status_macro/status_macros.h"
#include "tvs/proto/appraisal_policies.pb.h"

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

absl::StatusOr<AppraisalPolicies> PolicyFetcherGcp::GetLatestNPolicies(int n) {
  AppraisalPolicies appraisal_policies;
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          Policy
      FROM
          AppraisalPolicies
      ORDER BY UpdateTimestamp DESC
      LIMIT @limit)sql",
      {{"limit", google::cloud::spanner::Value(n)}});
  using RowType = std::tuple<google::cloud::spanner::Bytes>;
  auto rows = spanner_client_.ExecuteQuery(std::move(select));
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    AppraisalPolicy policy;
    if (!policy.ParseFromString(std::get<0>(*row).get<std::string>())) {
      return absl::FailedPreconditionError("Failed to parse a policy");
    }
    *appraisal_policies.add_policies() = std::move(policy);
  }
  if (appraisal_policies.policies_size() == 0) {
    return absl::NotFoundError("No policies found");
  }
  return appraisal_policies;
}

absl::StatusOr<AppraisalPolicies> PolicyFetcherGcp::GetLatestNPoliciesForDigest(
    absl::string_view application_digest, int n) {
  AppraisalPolicies appraisal_policies;
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          Policy
      FROM
          AppraisalPolicies
      WHERE ApplicationDigest = @application_digest
      ORDER BY UpdateTimestamp DESC
      LIMIT @limit)sql",
      {{"application_digest",
        google::cloud::spanner::Value(
            google::cloud::spanner::Bytes(application_digest))},
       {"limit", google::cloud::spanner::Value(n)}});
  using RowType = std::tuple<google::cloud::spanner::Bytes>;
  auto rows = spanner_client_.ExecuteQuery(std::move(select));
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    AppraisalPolicy policy;
    if (!policy.ParseFromString(std::get<0>(*row).get<std::string>())) {
      return absl::FailedPreconditionError("Failed to parse a policy");
    }
    *appraisal_policies.add_policies() = std::move(policy);
  }
  if (appraisal_policies.policies_size() == 0) {
    return absl::NotFoundError("No policies found");
  }
  return appraisal_policies;
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
