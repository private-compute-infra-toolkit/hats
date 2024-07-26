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

#ifndef HATS_KEY_MANAGER_KEY_MANAGER_FACTORY_H_
#define HATS_KEY_MANAGER_KEY_MANAGER_FACTORY_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"

namespace privacy_sandbox::key_manager {

class KeyFetcher {
 public:
  static std::unique_ptr<KeyFetcher> Create();
  virtual absl::StatusOr<std::string> GetPrimaryPrivateKey() = 0;
  virtual absl::StatusOr<std::string> GetSecondaryPrivateKey() = 0;
  virtual absl::StatusOr<std::string> GetSecret(
      const std::string& secret_id) = 0;
};

}  // namespace privacy_sandbox::key_manager

#endif  // HATS_KEY_MANAGER_KEY_MANAGER_FACTORY_H_
