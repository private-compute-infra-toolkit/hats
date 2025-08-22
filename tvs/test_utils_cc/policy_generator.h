// Copyright 2025 Google LLC.
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

#ifndef TVS_TEST_UTILS_CC_POLICY_GENERATOR_H_
#define TVS_TEST_UTILS_CC_POLICY_GENERATOR_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tvs/proto/appraisal_policies.pb.h"

namespace pcit::tvs::test_utils_cc {

// Creates and returns a fully-formed dynamic AppraisalPolicies proto
// for use in tests.
absl::StatusOr<AppraisalPolicies> CreateDynamicGenoaPolicy();

// Creates a policy set with one valid dynamic policy and one
// insecure policy.
absl::StatusOr<AppraisalPolicies> CreateMixedDynamicAndInsecurePolicies();

// Reads the stage0 bin, hashes it, and writes it to a file
// named with the hash inside the provided temporary directory.
absl::Status PopulateTempBlobDirectory(absl::string_view temp_dir_path);

}  // namespace pcit::tvs::test_utils_cc

#endif  // TVS_TEST_UTILS_CC_POLICY_GENERATOR_H_
