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

#ifndef HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_GCP_H_
#define HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_GCP_H_

#include <memory>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/spanner/client.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace privacy_sandbox::tvs {

class PolicyFetcherGcp final : public PolicyFetcher {
 public:
  PolicyFetcherGcp() = delete;
  PolicyFetcherGcp(absl::string_view project_id, absl::string_view instance_id,
                   absl::string_view database_id);
  // For unit-tests only.
  static std::unique_ptr<PolicyFetcher> Create(
      google::cloud::spanner::Client spanner_client);

  absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n) override;

  absl::StatusOr<AppraisalPolicies> GetLatestNPoliciesForDigest(
      absl::string_view application_digest, int n) override;

 private:
  // For unit-tests only.
  PolicyFetcherGcp(google::cloud::spanner::Client spanner_client);

  google::cloud::spanner::Client spanner_client_;
};

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_GCP_H_
