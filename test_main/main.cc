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

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "client/launcher/launcher.h"
#include "client/proto/launcher_config.pb.h"
#include "client/proto/trusted_service.pb.h"
#include "client/trusted_application/trusted_application_client.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "key_manager/key-fetcher.h"
#include "status_macro/status_macros.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/credentials/credentials.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/untrusted_tvs/tvs-service.h"

ABSL_FLAG(std::string, launcher_config_path, "",
          "path to read launcher configuration");
ABSL_FLAG(bool, use_tls, false,
          "whether to use tls when establishing gRPC channel to tvs server");
ABSL_FLAG(std::string, tvs_authentication_key, "",
          "HEX format authentication private key with public key pair shared "
          "with TVS "
          "instance to identify the specific launcher.");
ABSL_FLAG(std::string, tvs_access_token, "",
          "Oauth bearer token got from TVS hosting provider used to talk to "
          "TVS server");
ABSL_FLAG(std::vector<std::string>, private_key_wrapping_keys, {},
          "Comma-separated list of hex-encoded private key wrapping keys. Only "
          "the first key is used for encryption; additional keys are used only "
          "for decryption.");
ABSL_FLAG(int, tvs_listening_port, 7778, "Port TVS server listens to.");
ABSL_FLAG(bool, enable_policy_signature, false,
          "Whether to check signatures on policies");
ABSL_FLAG(std::string, application_key, "",
          "This should be the same value as the user_secret passed to the "
          "local key fetcher");
ABSL_FLAG(
    bool, qemu_log_to_std, false,
    "Whether to send qemu logs to stdout/stderr instead of a temporary file.");

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

  // Startup TVS
  std::unique_ptr<privacy_sandbox::key_manager::KeyFetcher> key_fetcher =
      privacy_sandbox::key_manager::KeyFetcher::Create();
  int tvs_listening_port = absl::GetFlag(FLAGS_tvs_listening_port);

  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::tvs::PolicyFetcher> policy_fetcher,
      privacy_sandbox::tvs::PolicyFetcher::Create(),
      _.PrependWith("Failed to create a policy fetcher: ").LogErrorAndExit());

  HATS_ASSIGN_OR_RETURN(
      privacy_sandbox::tvs::AppraisalPolicies appraisal_policies,
      policy_fetcher->GetLatestNPolicies(/*n=*/5),
      _.PrependWith("Failed to get appraisal policies: ").LogErrorAndExit());

  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::tvs::TvsService> tvs_service,
      privacy_sandbox::tvs::TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature =
              absl::GetFlag(FLAGS_enable_policy_signature),
          .accept_insecure_policies = false,
      }),
      _.PrependWith("Failed to create TVS server: ").LogErrorAndExit());

  LOG(INFO) << "Starting TVS server on port " << tvs_listening_port;

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder()
          .AddListeningPort(absl::StrCat("0.0.0.0:", tvs_listening_port),
                            grpc::InsecureServerCredentials())
          .RegisterService(tvs_service.get())
          .BuildAndStart();

  // we sleep here because otherwise, the launcher was trying to communicate
  // with the tvs before the port was bound
  std::this_thread::sleep_for(std::chrono::seconds(5));
  // Startup Launcher

  LOG(INFO) << "read configuration";
  // convert hex string to bytes as expected.
  std::string tvs_authentication_key_bytes;
  if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_tvs_authentication_key),
                              &tvs_authentication_key_bytes)) {
    LOG(ERROR) << "tvs authentication key should be in hex string format";
    return 1;
  }

  privacy_sandbox::client::PrivateKeyWrappingKeys wrapping_keys;
  bool primary = true;
  for (const std::string& key_hex :
       absl::GetFlag(FLAGS_private_key_wrapping_keys)) {
    std::string key_bytes;
    if (!absl::HexStringToBytes(key_hex, &key_bytes)) {
      LOG(ERROR) << "private key wrapping key should be in hex string format";
      return 1;
    }
    if (primary) {
      primary = false;

      wrapping_keys.set_primary(key_bytes);
      continue;
    }

    wrapping_keys.add_active(key_bytes);
  }

  HATS_ASSIGN_OR_RETURN(
      privacy_sandbox::client::LauncherConfig config,
      LoadConfig(absl::GetFlag(FLAGS_launcher_config_path)),
      _.PrependWith("Failed to fetch launcher config with error: ")
          .LogErrorAndExit());

  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;
  HATS_ASSIGN_OR_RETURN(
      std::shared_ptr<grpc::Channel> tvs_channel,
      privacy_sandbox::tvs::CreateGrpcChannel(
          privacy_sandbox::tvs::CreateGrpcChannelOptions{
              .use_tls = absl::GetFlag(FLAGS_use_tls),
              .target = absl::StrCat("localhost:",
                                     std::to_string(tvs_listening_port)),
              .access_token = absl::GetFlag(FLAGS_tvs_access_token),
          }),
      _.PrependWith("Failed to establish gRPC channel to TVS server")
          .LogErrorAndExit());
  channel_map[0] = std::move(tvs_channel);

  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<privacy_sandbox::client::HatsLauncher> launcher,
      privacy_sandbox::client::HatsLauncher::Create({
          .config = std::move(config),
          .tvs_authentication_key_bytes =
              std::move(tvs_authentication_key_bytes),
          .private_key_wrapping_keys = std::move(wrapping_keys),
          .tvs_channels = std::move(channel_map),
          .qemu_log_to_std = absl::GetFlag(FLAGS_qemu_log_to_std),
      }),
      _.PrependWith("Failed to create launcher: ").LogErrorAndExit());

  // Generate the log file randomly.
  HATS_RETURN_IF_ERROR(launcher->Start())
      .PrependWith("Launcher terminated with abnormal status: ")
      .LogErrorAndExit();

  // Now here we need to check if app is ready, if it is, start up app client
  // and talk to it.
  while (!launcher->IsAppReady()) {
    std::cout << "Waiting for app to be ready" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
  }

  std::string app_key;
  if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_application_key), &app_key)) {
    LOG(ERROR) << "application key should be in hex string format";
    return 1;
  }
  privacy_sandbox::client::TrustedApplicationClient app_client =
      privacy_sandbox::client::TrustedApplicationClient(app_key, 64);

  HATS_ASSIGN_OR_RETURN(
      privacy_sandbox::client::DecryptedResponse response,
      app_client.SendEcho(),
      _.PrependWith("Failed to communicate with trusted application: ")
          .LogErrorAndExit());

  std::cout << *response.mutable_response();
  launcher->Shutdown();
  tvs_server->Shutdown();
  return 0;
}
