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

#include "gcp_common/gcp-status.h"

#include "absl/status/status.h"
#include "google/cloud/status.h"

namespace pcit::gcp_common {

// Not casting since there is no guarantee of values being synced
absl::Status GcpToAbslStatus(const google::cloud::Status& status) {
  switch (status.code()) {
    case google::cloud::StatusCode::kOk:
      return absl::OkStatus();
    case google::cloud::StatusCode::kNotFound:
      return absl::NotFoundError(status.message());
    case google::cloud::StatusCode::kPermissionDenied:
      return absl::PermissionDeniedError(status.message());
    case google::cloud::StatusCode::kInvalidArgument:
      return absl::InvalidArgumentError(status.message());
    case google::cloud::StatusCode::kCancelled:
      return absl::CancelledError(status.message());
    case google::cloud::StatusCode::kUnknown:
      return absl::UnknownError(status.message());
    case google::cloud::StatusCode::kAlreadyExists:
      return absl::AlreadyExistsError(status.message());
    case google::cloud::StatusCode::kResourceExhausted:
      return absl::ResourceExhaustedError(status.message());
    case google::cloud::StatusCode::kFailedPrecondition:
      return absl::FailedPreconditionError(status.message());
    case google::cloud::StatusCode::kAborted:
      return absl::AbortedError(status.message());
    case google::cloud::StatusCode::kUnimplemented:
      return absl::UnimplementedError(status.message());
    case google::cloud::StatusCode::kOutOfRange:
      return absl::OutOfRangeError(status.message());
    case google::cloud::StatusCode::kInternal:
      return absl::InternalError(status.message());
    case google::cloud::StatusCode::kUnavailable:
      return absl::UnavailableError(status.message());
    case google::cloud::StatusCode::kDataLoss:
      return absl::DataLossError(status.message());
    case google::cloud::StatusCode::kUnauthenticated:
      return absl::UnauthenticatedError(status.message());
    case google::cloud::StatusCode::kDeadlineExceeded:
      return absl::DeadlineExceededError(status.message());
  }
  // Return unknown error if there is no match.
  // Not default so that error raised by new types
  return absl::UnknownError(status.message());
}

}  // namespace pcit::gcp_common
