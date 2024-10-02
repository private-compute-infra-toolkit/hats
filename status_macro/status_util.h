// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HATS_STATUS_MACRO_STATUS_UTIL_H_
#define HATS_STATUS_MACRO_STATUS_UTIL_H_

#include "absl/status/status.h"
#include "google/rpc/status.pb.h"
#include "grpcpp/grpcpp.h"  // IWYU pragma: keep

namespace privacy_sandbox::status_macro {

// Converts from absl::Status to grpc::Status.
grpc::Status FromAbslStatus(const absl::Status& status);

// Converts from grpc::Status to absl::Status.
absl::Status ToAbslStatus(const grpc::Status& status);

inline google::rpc::Status SaveStatusAsRpcStatus(const absl::Status& status) {
  google::rpc::Status ret;
  ret.set_code(static_cast<int>(status.code()));
  ret.set_message(status.message());
  return ret;
}

}  // namespace privacy_sandbox::status_macro

#endif  // HATS_STATUS_MACRO_STATUS_UTIL_H_
