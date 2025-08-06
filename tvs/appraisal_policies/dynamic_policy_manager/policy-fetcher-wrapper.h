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

#ifndef HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_WRAPPER_H_
#define HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_WRAPPER_H_

#include <memory>

#include "include/cxx.h"
#include "tvs/appraisal_policies/policy-fetcher.h"

namespace pcit::tvs::trusted {

// Forward declaration for the shared types. We cannot include the header
// generated from rust as we are redefining KeyFetcherWrapper in there.
struct VecU8Result;

// Wrapper class around `tvs::PolicyFetcher` methods to make it usable to
// Rust code. Due to the limitation in the FFI, methods exported to rust has to
// be marked as `const` even if they are not.
// Furthermore, the rust bridge does not know how to convert C++ errors besides
// exception to Rust error. Instead of changing
// `tvs/appraisal_policies/policy-fetcher.h` to be compatible with cxx.rs
// bridge, we write a wrapper.
// Each method returns a struct that contains either a value or an error
// message to emulate C++ absl::StatusOr and Rust Result.
class PolicyFetcherWrapper final {
 public:
  explicit PolicyFetcherWrapper(std::unique_ptr<PolicyFetcher> policy_fetcher);

  VecU8Result GetLatestNPoliciesForDigest(
      rust::Slice<const uint8_t> application_digest, int n) const;

 private:
  std::unique_ptr<PolicyFetcher> policy_fetcher_;
};

}  // namespace pcit::tvs::trusted

#endif  // HATS_TVS_APPRAISAL_POLICIES_POLICY_FETCHER_WRAPPER_H_
