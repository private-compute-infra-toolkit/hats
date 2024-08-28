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

#ifndef HATS_CLIENT_LAUNCHER_CERTIFICATES_H_
#define HATS_CLIENT_LAUNCHER_CERTIFICATES_H_

#include <string>

#include "absl/status/statusor.h"

namespace privacy_sandbox::client {
absl::StatusOr<std::string> DownloadCertificate(const std::string& url);
}  // namespace privacy_sandbox::client
#endif  // HATS_CLIENT_LAUNCHER_CERTIFICATES_
