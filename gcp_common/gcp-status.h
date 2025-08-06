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

#ifndef HATS_GCP_COMMON_GCP_STATUS_H_
#define HATS_GCP_COMMON_GCP_STATUS_H_

#include "absl/status/status.h"
#include "google/cloud/status.h"

namespace pcit::gcp_common {

absl::Status GcpToAbslStatus(const google::cloud::Status& status);

}  // namespace pcit::gcp_common

#endif  // HATS_GCP_COMMON_GCP_STATUS_H_
