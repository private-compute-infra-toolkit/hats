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

class PolicyFetcherLocal final : public PolicyFetcher {
 public:
  PolicyFetcherLocal() = delete;
  PolicyFetcherLocal(AppraisalPolicies policies)
      : policies_(std::move(policies)) {}

  // Arbitrary return `n` policies as we don't have update timestamp
  // in the file, and we don't need them as we can always create new
  absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n) {
    AppraisalPolicies result;
    for (int i = 0; i < n && i < policies_.policies_size(); ++i) {
      *result.add_policies() = policies_.policies()[i];
    }
    return policies_;
  }

 private:
  const AppraisalPolicies policies_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create() {
  absl::StatusOr<AppraisalPolicies> policies =
      ReadAppraisalPolicies(absl::GetFlag(FLAGS_appraisal_policy_file));
  if (!policies.ok()) return policies.status();
  return std::make_unique<PolicyFetcherLocal>(*std::move(policies));
}

}  // namespace privacy_sandbox::tvs
