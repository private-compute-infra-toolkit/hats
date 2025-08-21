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

#ifndef HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_H_
#define HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace pcit::tvs {

class PolicyFetcher {
 public:
  static absl::StatusOr<std::unique_ptr<PolicyFetcher>> Create();
  static absl::StatusOr<std::unique_ptr<PolicyFetcher>> Create(
      const std::string& file_path);
  static absl::StatusOr<std::unique_ptr<PolicyFetcher>> CreateWithBlobs(
      const std::string& file_path,
      const std::string& stage0_blob_directory_path);
  virtual ~PolicyFetcher() = default;

  // Get latest `n` policies. The method retrieve the last `n` inserted
  // appraisal policies from the storage.
  virtual absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n) = 0;

  // Get latest `n` policies that have `application_digest` in the
  // container_binary_sha256 field.
  // Note that the application_digest is in binary representation (versus hex
  // digit string).
  virtual absl::StatusOr<AppraisalPolicies> GetLatestNPoliciesForDigest(
      absl::string_view application_digest, int n) = 0;
};

}  // namespace pcit::tvs

#endif  // HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_H_
