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
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "gcp_common/flags.h"
#include "google/cloud/spanner/client.h"
#include "google/cloud/spanner/sql_statement.h"
#include "status_macro/status_macros.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace pcit::tvs {

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

#if defined(DYNAMIC_ATTESTATION)
  google::cloud::spanner::SqlStatement select(
      R"sql(
      WITH
          LatestPolicies AS (
              SELECT
                  PolicyId, Policy, UpdateTimestamp
              FROM
                  AppraisalPolicies
              ORDER BY
                  UpdateTimestamp DESC
              LIMIT @limit)
      SELECT
          lp.PolicyID, lp.Policy, b.Sha256Digest, b.BlobData
      FROM
          LatestPolicies AS lp
      LEFT JOIN
          Stage0BlobToPolicy AS link ON lp.PolicyId = link.PolicyId
      LEFT JOIN
          Stage0Blobs AS b ON link.Sha256Digest = b.Sha256Digest
      ORDER BY
          lp.UpdateTimestamp DESC
      )sql",
      {{"limit", google::cloud::spanner::Value(n)}});
  // RowType has columns from all three tables
  using RowType =
      std::tuple<int64_t,                                       // PolicyId
                 google::cloud::spanner::Bytes,                 // Policy
                 std::optional<google::cloud::spanner::Bytes>,  // Sha256Digest
                 std::optional<google::cloud::spanner::Bytes>   // BlobData
                 >;

  // helper map to keep track of policies that have been added to
  // AppraisalPolicies object
  absl::flat_hash_map<int64_t, AppraisalPolicy*> added_policies;

  auto rows = spanner_client_.ExecuteQuery(std::move(select));
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    int64_t policy_id = std::get<0>(*row);
    // Add policy to map if it has not been added yet
    if (!added_policies.contains(policy_id)) {
      // Directly add a new policy to the result and get a pointer to it.
      AppraisalPolicy* new_policy = appraisal_policies.add_policies();
      if (!new_policy->ParseFromString(std::get<1>(*row).get<std::string>())) {
        return absl::FailedPreconditionError("Failed to parse a policy");
      }
      // Store the pointer in our helper map.
      added_policies[policy_id] = new_policy;
    }

    // Add the stage 0 blob data to the policy if it exists
    auto sha256_bytes_optional = std::get<2>(*row);
    auto blob_data_optional = std::get<3>(*row);
    if (sha256_bytes_optional && blob_data_optional) {
      std::string sha256_digest =
          absl::BytesToHexString(sha256_bytes_optional->get<std::string>());
      (*appraisal_policies
            .mutable_stage0_binary_sha256_to_blob())[sha256_digest] =
          blob_data_optional->get<std::string>();
    }
  }
#else
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
#endif  // defined(DYNAMIC_ATTESTATION)

  if (appraisal_policies.policies_size() == 0) {
    return absl::NotFoundError("No policies found");
  }
  return appraisal_policies;
}

absl::StatusOr<AppraisalPolicies> PolicyFetcherGcp::GetLatestNPoliciesForDigest(
    absl::string_view application_digest, int n) {
  AppraisalPolicies appraisal_policies;

#if defined(DYNAMIC_ATTESTATION)
  google::cloud::spanner::SqlStatement select(
      R"sql(
    WITH LatestPoliciesforDigest AS (
        SELECT
            p.PolicyId, p.Policy, p.UpdateTimestamp
        FROM
            AppraisalPolicies as p
        JOIN
            ApplicationDigests as d ON p.PolicyId = d.PolicyId
        WHERE
            d.ApplicationDigest = @application_digest
        ORDER BY
            p.UpdateTimestamp DESC
        LIMIT @limit
    )
    SELECT
        lp.PolicyID, lp.Policy, b.Sha256Digest, b.BlobData
    FROM
        LatestPoliciesForDigest AS lp
    LEFT JOIN
        Stage0BlobToPolicy AS link ON lp.PolicyId = link.PolicyId
    LEFT JOIN
        Stage0Blobs AS b ON link.Sha256Digest = b.Sha256Digest
    ORDER BY
        lp.UpdateTimestamp DESC
    )sql",
      {{"application_digest",
        google::cloud::spanner::Value(
            google::cloud::spanner::Bytes(application_digest))},
       {"limit", google::cloud::spanner::Value(n)}});

  // RowType has columns from all three tables
  using RowType =
      std::tuple<int64_t,                                       // PolicyId
                 google::cloud::spanner::Bytes,                 // Policy
                 std::optional<google::cloud::spanner::Bytes>,  // Sha256Digest
                 std::optional<google::cloud::spanner::Bytes>   // BlobData
                 >;

  // helper map to keep track of policies that have been added to
  // AppraisalPolicies object
  absl::flat_hash_map<int64_t, AppraisalPolicy*> added_policies;

  auto rows = spanner_client_.ExecuteQuery(std::move(select));
  for (auto& row : google::cloud::spanner::StreamOf<RowType>(rows)) {
    HATS_RETURN_IF_ERROR(row.status());
    int64_t policy_id = std::get<0>(*row);
    // Add policy to map if it has not been added yet
    if (!added_policies.contains(policy_id)) {
      // Directly add a new policy to the result and get a pointer to it.
      AppraisalPolicy* new_policy = appraisal_policies.add_policies();
      if (!new_policy->ParseFromString(std::get<1>(*row).get<std::string>())) {
        return absl::FailedPreconditionError("Failed to parse a policy");
      }
      // Store pointer in helper map to avoid duplicating policy object if
      // associated w multiple blobs
      added_policies[policy_id] = new_policy;
    }

    // Add the stage 0 blob data to the policy if it exists
    auto sha256_bytes_optional = std::get<2>(*row);
    auto blob_data_optional = std::get<3>(*row);
    if (sha256_bytes_optional && blob_data_optional) {
      std::string sha256_digest =
          absl::BytesToHexString(sha256_bytes_optional->get<std::string>());
      (*appraisal_policies
            .mutable_stage0_binary_sha256_to_blob())[sha256_digest] =
          blob_data_optional->get<std::string>();
    }
  }
#else
  google::cloud::spanner::SqlStatement select(
      R"sql(
      SELECT
          p.Policy
      FROM
          AppraisalPolicies AS p
      JOIN
          ApplicationDigests AS d ON p.PolicyId = d.PolicyId
      WHERE
          d.ApplicationDigest = @application_digest
      ORDER BY
          p.UpdateTimestamp DESC
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
#endif  // defined(DYNAMIC_ATTESTATION)
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

}  // namespace pcit::tvs
