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
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "status_macro/status_macros.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"

ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");

namespace privacy_sandbox::tvs {

namespace {

absl::StatusOr<AppraisalPolicies> ReadAppraisalPolicies(
    absl::string_view filename) {
  std::ifstream if_stream({std::string(filename)});
  if (!if_stream.is_open()) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to open: ", filename));
  }
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::Parse(&istream, &appraisal_policies)) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to parse: ", filename));
  }
  return appraisal_policies;
}

absl::StatusOr<std::unordered_map<std::string, AppraisalPolicies>>
IndexAppraisalPolicies(AppraisalPolicies appraisal_policies) {
  std::unordered_map<std::string, AppraisalPolicies> indexed_appraisal_policies;
  // Use non-const to enable effective use of std::move().
  for (AppraisalPolicy& appraisal_policy :
       *appraisal_policies.mutable_policies()) {
    std::string application_digest;
    if (!absl::HexStringToBytes(
            appraisal_policy.measurement().container_binary_sha256(),
            &application_digest)) {
      return absl::InvalidArgumentError(
          "Failed to parse application digest. The digest should be in "
          "formatted as "
          "hex string.");
    }
    // operator[] inserts a key with default value if not there; otherwise it
    // returns the value for that key. We then insert the given policy.
    AppraisalPolicies& policies =
        indexed_appraisal_policies[application_digest];
    *policies.add_policies() = std::move(appraisal_policy);
  }
  return indexed_appraisal_policies;
}

class PolicyFetcherLocal final : public PolicyFetcher {
 public:
  PolicyFetcherLocal() = delete;
  PolicyFetcherLocal(
      std::unordered_map<std::string, AppraisalPolicies> policies)
      : policies_(std::move(policies)) {}

  // Arbitrary return `n` policies as we don't have update timestamp
  // in the file.
  absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n) override {
    // Number of policies found;
    int counter = 0;
    AppraisalPolicies result;
    for (const auto& [_, policies] : policies_) {
      for (const AppraisalPolicy& policy : policies.policies()) {
        *result.add_policies() = policy;
        if (++counter == n) return result;
      }
    }

    if (result.policies().size() == 0) {
      return absl::NotFoundError("No policies found");
    }
    return result;
  }

  // Arbitrary return `n` policies as we don't have update timestamp
  // in the file.
  absl::StatusOr<AppraisalPolicies> GetLatestNPoliciesForDigest(
      absl::string_view application_digest, int n) override {
    // Number of policies found;
    int counter = 0;
    AppraisalPolicies result;
    if (auto it = policies_.find(std::string(application_digest));
        it != policies_.end()) {
      for (const AppraisalPolicy& policy : it->second.policies()) {
        *result.add_policies() = policy;
        if (++counter == n) return result;
      }
    }

    if (result.policies().size() == 0) {
      return absl::NotFoundError("No policies found");
    }
    return result;
  }

 private:
  // Policies keyed by application digest i.e. container_binary_sha256 filed.
  // The key is the byte representation of the digest.
  const std::unordered_map<std::string, AppraisalPolicies> policies_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create() {
  HATS_ASSIGN_OR_RETURN(
      AppraisalPolicies policies,
      ReadAppraisalPolicies(absl::GetFlag(FLAGS_appraisal_policy_file)));
  std::unordered_map<std::string, AppraisalPolicies> indexed_appraisal_policies;
  HATS_ASSIGN_OR_RETURN(indexed_appraisal_policies,
                        IndexAppraisalPolicies(std::move(policies)));
  return std::make_unique<PolicyFetcherLocal>(
      std::move(indexed_appraisal_policies));
}

absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create(
    const std::string& file_path) {
  HATS_ASSIGN_OR_RETURN(AppraisalPolicies policies,
                        ReadAppraisalPolicies(file_path));
  std::unordered_map<std::string, AppraisalPolicies> indexed_appraisal_policies;
  HATS_ASSIGN_OR_RETURN(indexed_appraisal_policies,
                        IndexAppraisalPolicies(std::move(policies)));
  return std::make_unique<PolicyFetcherLocal>(
      std::move(indexed_appraisal_policies));
}

}  // namespace privacy_sandbox::tvs
