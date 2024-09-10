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
#include "absl/strings/escaping.h"
#include "client/launcher/launcher.h"
#include "client/proto/launcher_config.pb.h"
#include "google/protobuf/text_format.h"
#include "tvs/credentials/credentials.h"

ABSL_FLAG(std::string, launcher_config_path, "./launcher_config.textproto",
          "path to read launcher configuration");
ABSL_FLAG(std::string, tvs_address, "localhost:7779",
          "TVS address to talk to to fetch private keys.");
// MUST PASS ADDRESSES IN SAME ORDER AS ORCHESTRATOR WILL RECEIVE THEM
ABSL_FLAG(std::vector<std::string>, tvs_addresses,
          std::vector<std::string>({""}),
          "Comma separated list of tvs addresses to use in the following format"
          "<tvs address 1>, <tvs address 2>");
ABSL_FLAG(bool, use_tls, false,
          "whether to use tls when establishing gRPC channel to tvs server");
ABSL_FLAG(std::string, tvs_authentication_key, "",
          "HEX format authentication private key with public key pair shared "
          "with TVS "
          "instance to identify the specific launcher.");
ABSL_FLAG(std::string, tvs_access_token, "",
          "Oauth bearer token got from TVS hosting provider used to talk to "
          "TVS server");
ABSL_FLAG(std::string, qemu_log_filename, "",
          "When provided, qemu will send std logs into the specific log file "
          "path instead of a randomly generated path in tmp");

absl::StatusOr<privacy_sandbox::client::LauncherConfig> LoadConfig(
    absl::string_view path) {
  std::ifstream file(path.data());
  if (!file.is_open()) {
    return absl::InvalidArgumentError(
        absl::StrCat("failed to open file '", path, "'"));
  }
  std::string raw_config((std::istreambuf_iterator<char>(file)),
                         (std::istreambuf_iterator<char>()));
  file.close();
  privacy_sandbox::client::LauncherConfig config;
  if (!google::protobuf::TextFormat::ParseFromString(raw_config, &config)) {
    return absl::InvalidArgumentError(
        absl::StrCat("invalid prototext message at path '", path, "'"));
  }

  return config;
}

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();
  LOG(INFO) << "read configuration";
  std::string tvs_authentication_key =
      absl::GetFlag(FLAGS_tvs_authentication_key);
  // convert hex string to bytes as expected.
  std::string tvs_authentication_key_bytes;
  if (!absl::HexStringToBytes(tvs_authentication_key,
                              &tvs_authentication_key_bytes)) {
    LOG(ERROR) << "tvs authentication key should be in hex string format";
    return 1;
  }
  absl::StatusOr<privacy_sandbox::client::LauncherConfig> config =
      LoadConfig(absl::GetFlag(FLAGS_launcher_config_path));
  if (!config.ok()) {
    LOG(ERROR) << "Failed to fetch launcher config with error: "
               << config.status();
    return 1;
  }

  privacy_sandbox::client::HatsLauncherConfig hats_config{
      .config = *std::move(config),
      .tvs_authentication_key_bytes = std::move(tvs_authentication_key_bytes)};

  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;
  int64_t tvs_id = 0;
  for (const std::string& tvs_address : absl::GetFlag(FLAGS_tvs_addresses)) {
    absl::StatusOr<std::shared_ptr<grpc::Channel>> tvs_channel =
        privacy_sandbox::tvs::CreateGrpcChannel(privacy_sandbox::tvs::CreateGrpcChannelOptions{
        .use_tls = absl::GetFlag(FLAGS_use_tls),
        .target = tvs_address,
        .access_token = absl::GetFlag(FLAGS_tvs_access_token),
    });
    if (!tvs_channel.ok()) {
      LOG(ERROR) << "Failed to establish gRPC channel to TVS server"
                 << tvs_channel.status();
      return 1;
    }
    channel_map[tvs_id++] = *std::move(tvs_channel);
  }

  absl::StatusOr<std::unique_ptr<privacy_sandbox::client::HatsLauncher>>
      launcher = privacy_sandbox::client::HatsLauncher::Create(
          std::move(hats_config), std::move(channel_map));
  if (!launcher.ok()) {
    LOG(ERROR) << "Failed to create launcher: " << launcher.status();
    return 1;
  }

  // Generate the log file randomly.
  if (absl::Status status =
          (*launcher)->Start(absl::GetFlag(FLAGS_qemu_log_filename));
      !status.ok()) {
    LOG(ERROR) << "launcher terminated with abnormal status "
               << status.message();
    return 1;
  }

  (*launcher)->Wait();
  return 0;
}
