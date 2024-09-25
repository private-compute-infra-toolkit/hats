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

#include "absl/base/nullability.h"
#include "absl/flags/declare.h"
#include "absl/strings/string_view.h"
#include "client/launcher/launcher-server.h"
#include "client/launcher/logs-service.h"
#include "client/launcher/qemu.h"
#include "client/proto/launcher_config.pb.h"
#include "external/google_privacysandbox_servers_common/src/parc/servers/local/parc_server.h"

namespace privacy_sandbox::client {

// External dependencies to the file system or other places for the launcher to
// be healthy.
struct LauncherExtDeps {
  std::string kernel_binary_path;
  std::string stage0_binary_path;
  std::string initrd_cpio_xz_path;
  std::string oak_system_image_path;
  std::string container_bundle;
  std::string vmm_binary_path;
};

struct HatsLauncherConfig {
  // Config file provided configurations.
  LauncherConfig config;
  // Flag provided configurations.
  std::string tvs_authentication_key_bytes;
  PrivateKeyWrappingKeys private_key_wrapping_keys;
};

// HatsLauncher untars the hats bundle into a hosted location:
// /tmp/hats-XXXXX/. The folder is owned by the process owner.
class HatsLauncher final {
 public:
  HatsLauncher() = delete;
  HatsLauncher(const HatsLauncher&) = delete;
  HatsLauncher& operator=(const HatsLauncher&) = delete;

  static absl::StatusOr<std::unique_ptr<HatsLauncher>> Create(
      const HatsLauncherConfig& config,
      const std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>&
          channel_map);

  // Terminate all services and subprocesses.
  void Shutdown() ABSL_LOCKS_EXCLUDED(mu_);

  uint32_t GetVsockPort() const;

  std::optional<uint16_t> GetTcpPort() const;

  absl::StatusOr<std::string> GetQemuLogFilename();

  // Wait for the process ready to receive requests.
  void WaitUntilReady() ABSL_LOCKS_EXCLUDED(mu_);

  // Wait for termination. Return immediately if the server is not started.
  void Wait() ABSL_LOCKS_EXCLUDED(mu_);

  // Run QEMU server and launcher service.
  // This function should be called only once to ensure server states are clean.
  absl::Status Start(absl::string_view qemu_log_filename)
      ABSL_LOCKS_EXCLUDED(mu_);

  bool IsAppReady() const;

 private:
  HatsLauncher(
      LauncherExtDeps deps, absl::Nonnull<std::unique_ptr<Qemu>> qemu,
      absl::Nonnull<std::unique_ptr<LauncherOakServer>> launcher_oak_server,
      absl::Nonnull<std::unique_ptr<LauncherServer>> launcher_server,
      absl::Nonnull<std::unique_ptr<LogsService>> logs_service,
      absl::Nonnull<std::unique_ptr<grpc::Server>> vsock_server,
      uint32_t vsock_port,
      absl::Nullable<
          std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
          parc_server,
      absl::Nullable<std::unique_ptr<grpc::Server>> tcp_server,
      std::optional<uint16_t> tcp_port);

  // The external dependencies are not owned by HatsLauncher but required
  // for system health.
  const LauncherExtDeps deps_;
  absl::Nonnull<std::unique_ptr<Qemu>> qemu_;
  absl::Nonnull<std::unique_ptr<LauncherOakServer>> launcher_oak_server_;
  absl::Nonnull<std::unique_ptr<LauncherServer>> launcher_server_;
  absl::Nonnull<std::unique_ptr<LogsService>> logs_service_;
  std::unique_ptr<grpc::Server> vsock_server_;
  uint32_t vsock_port_;
  // Parc server is null when it's not specified.
  absl::Nullable<std::unique_ptr<privacysandbox::parc::local::v0::ParcServer>>
      parc_server_;
  // Tcp server is null when Parc is not enabled.
  absl::Nullable<std::unique_ptr<grpc::Server>> tcp_server_;
  std::optional<uint16_t> tcp_port_;

  // Whether all underlying processes was started or not.
  // The mutex is only for controlling access to started_.
  mutable absl::Mutex mu_;
  bool started_ ABSL_GUARDED_BY(mu_) = false;
};
}  // namespace privacy_sandbox::client

#endif
