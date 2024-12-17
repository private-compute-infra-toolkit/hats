// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tvs/appraisal_policies/dynamic_policy_manager/policy-fetcher-wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "tvs/appraisal_policies/dynamic_policy_manager/src/lib.rs.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace privacy_sandbox::tvs::trusted {

PolicyFetcherWrapper::PolicyFetcherWrapper(
    std::unique_ptr<PolicyFetcher> policy_fetcher)
    : policy_fetcher_(std::move(policy_fetcher)) {}

VecU8Result PolicyFetcherWrapper::GetLatestNPoliciesForDigest(
    rust::Slice<const uint8_t> application_digest, int n) const {
  std::string serialized_policies;
  {
    absl::StatusOr<AppraisalPolicies> policies =
        policy_fetcher_->GetLatestNPoliciesForDigest(
            std::string(
                reinterpret_cast<const char*>(application_digest.data()),
                application_digest.size()),
            n);
    if (!policies.ok()) {
      return {
          .error = "No matching appraisal policies",
      };
    }
    serialized_policies = policies->SerializeAsString();
  }
  rust::Vec<uint8_t> v;
  std::move(serialized_policies.begin(), serialized_policies.end(),
            std::back_inserter(v));
  return VecU8Result{
      .value = std::move(v),
  };
}

}  // namespace privacy_sandbox::tvs::trusted
