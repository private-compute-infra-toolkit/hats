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

#ifndef HATS_CLIENT_LAUNCHER_LAUNCHER_H_
#define HATS_CLIENT_LAUNCHER_LAUNCHER_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "client/proto/launcher_config.pb.h"

namespace privacy_sandbox::client {

// HatsLauncher untars the hats bundle into a hosted location:
// /tmp/hats-XXXXX/. The folder is owned by the process owner.
class HatsLauncher final {
 public:
  HatsLauncher() = delete;
  HatsLauncher(const HatsLauncher&) = delete;
  HatsLauncher& operator=(const HatsLauncher&) = delete;
  static absl::StatusOr<std::unique_ptr<HatsLauncher>> Create(
      const LauncherConfig& config);
  std::string GetKernelBinaryPath();
  std::string GetSystemImageTarXzPath();
  std::string GetStage0BinaryPath();
  std::string GetInitrdCpioXzPath();

 private:
  HatsLauncher(std::string hats_bundle_dir);
  const std::string kernel_binary_path_;
  const std::string system_image_tar_xz_path_;
  const std::string stage0_binary_path_;
  const std::string initrd_cpio_xz_path_;
};
}  // namespace privacy_sandbox::client

#endif
