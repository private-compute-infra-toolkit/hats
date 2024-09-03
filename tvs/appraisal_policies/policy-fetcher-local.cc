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

#include <fstream>

#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "proto/attestation/reference_value.pb.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"

ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");

namespace privacy_sandbox::tvs {

namespace {

absl::StatusOr<AppraisalPolicies::SignedAppraisalPolicy> ReadAppraisalPolicy(
    absl::string_view filename) {
  std::ifstream if_stream({std::string(filename)});
  if (!if_stream.is_open()) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to open: ", filename));
  }
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  AppraisalPolicies::SignedAppraisalPolicy appraisal_policy;
  if (!google::protobuf::TextFormat::Parse(&istream, &appraisal_policy)) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to parse: ", filename));
  }
  return appraisal_policy;
}

}  // namespace

class PolicyFetcherLocal final : public PolicyFetcher {
 public:
  PolicyFetcherLocal() = delete;
  PolicyFetcherLocal(AppraisalPolicies::SignedAppraisalPolicy policy)
      : policy_(std::move(policy)) {}

  // Always return one same policy.
  absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n) {
    AppraisalPolicies appraisal_policies;
    *appraisal_policies.add_signed_policy() = policy_;
    return appraisal_policies;
  }

 private:
  AppraisalPolicies::SignedAppraisalPolicy policy_;
};

absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create() {
  absl::StatusOr<AppraisalPolicies::SignedAppraisalPolicy> policy =
      ReadAppraisalPolicy(absl::GetFlag(FLAGS_appraisal_policy_file));
  if (!policy.ok()) return policy.status();
  return std::make_unique<PolicyFetcherLocal>(*std::move(policy));
}

}  // namespace privacy_sandbox::tvs
