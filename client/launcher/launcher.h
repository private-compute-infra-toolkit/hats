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
#include <unordered_map>

#include "client/proto/launcher.pb.h"
#include "client/proto/launcher_config.pb.h"
#include "grpcpp/channel.h"

namespace privacy_sandbox::client {

struct HatsLauncherConfig {
  // Config file provided configurations.
  LauncherConfig config;
  // Flag provided configurations.
  std::string tvs_authentication_key_bytes;
  PrivateKeyWrappingKeys private_key_wrapping_keys;
  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> tvs_channels;
  bool qemu_log_to_std = false;
};

// HatsLauncher untars the hats bundle into a hosted location:
// /tmp/hats-XXXXX/. The folder is owned by the process owner.
class HatsLauncher {
 public:
  static absl::StatusOr<std::unique_ptr<HatsLauncher>> Create(
      const HatsLauncherConfig& config);

  virtual ~HatsLauncher() = default;

  // Terminate all services and subprocesses.
  virtual void Shutdown() = 0;

  virtual uint32_t GetVsockPort() const = 0;

  virtual std::optional<uint16_t> GetTcpPort() const = 0;

  virtual absl::StatusOr<std::string> GetQemuLogFilename() const = 0;

  // Wait for the process ready to receive requests.
  virtual void WaitUntilReady() = 0;

  // Wait for termination. Return immediately if the server is not started.
  virtual void Wait() = 0;

  // Run QEMU server and launcher service.
  // This function should be called only once to ensure server states are clean.
  virtual absl::Status Start() = 0;

  // Whether the enclave app ready for service.
  virtual bool IsAppReady() const = 0;

  // Whether qemu has exited with an error
  virtual bool CheckStatus() const = 0;
};

}  // namespace privacy_sandbox::client

#endif  // HATS_CLIENT_LAUNCHER_LAUNCHER_H_
