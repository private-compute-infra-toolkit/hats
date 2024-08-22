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

#include <fstream>
#include <iostream>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "client/launcher/launcher.h"
#include "client/proto/launcher_config.pb.h"
#include "google/protobuf/text_format.h"
ABSL_FLAG(std::string, launcher_config_path, "./launcher_config.textproto",
          "path to read launcher configuration");
int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  privacy_sandbox::client::LauncherConfig config;
  std::string launcher_config_path = absl::GetFlag(FLAGS_launcher_config_path);
  if (launcher_config_path.empty()) {
    LOG(ERROR)
        << "empty launcher_config_path flag, expect some valid path to file.";
    return 1;
  }

  std::ifstream file(launcher_config_path);
  if (!file.is_open()) {
    LOG(ERROR) << "failed to open file " << launcher_config_path;
    return 1;
  }
  std::string raw_config((std::istreambuf_iterator<char>(file)),
                         (std::istreambuf_iterator<char>()));
  file.close();

  if (!google::protobuf::TextFormat::ParseFromString(raw_config, &config)) {
    LOG(ERROR) << "invalid json string message at path "
               << launcher_config_path;
    return 1;
  }

  absl::StatusOr<std::unique_ptr<privacy_sandbox::client::HatsLauncher>>
      launcher = privacy_sandbox::client::HatsLauncher::Create(config);
  if (!launcher.ok()) {
    LOG(ERROR) << "Failed to create launcher: " << launcher.status();
    return 1;
  }
  if (absl::Status status = (*launcher)->Start(); !status.ok()) {
    LOG(ERROR) << "launcher terminated with abnormal status "
               << status.message();
    return 1;
  }

  return 0;
}
