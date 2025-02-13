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
#include <vector>

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
#include "crypto/test-ec-key.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "gtest/gtest.h"
#include "key_manager/test-key-fetcher.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/credentials/credentials.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/standalone_server/tvs-service.h"

const int kUserId = 64;
const char kAppKey[] =
    "0e4fb4a3b7a7eeb42306db3cbc6108a2424bf8ef510101059b2edef36fe1687f";
const char kLauncherConfig[] = "launcher_config.prototext";
const char kAppraisalPolicy[] = "appraisal_policy.prototext";
// TODO: Generate key here when we no longer bake the keys into the system
// image.
const char kTvsPrimaryKey[] =
    "0000000000000000000000000000000000000000000000000000000000000001";

absl::StatusOr<std::string> GetSelfPath() {
  char buf[PATH_MAX + 1];
  ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf));
  if (len == -1)
    return absl::NotFoundError("Failed to get the executable path.");
  if (len >= PATH_MAX)
    return absl::OutOfRangeError("Executable path is too long.");
  return std::string(buf, len);
}

absl::StatusOr<std::string> GetRunfilePath(absl::string_view filename) {
  HATS_ASSIGN_OR_RETURN(std::string self_path, GetSelfPath());
  std::string runfiles_error;
  auto runfiles = bazel::tools::cpp::runfiles::Runfiles::Create(
      self_path, BAZEL_CURRENT_REPOSITORY, &runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  return runfiles->Rlocation(
      absl::StrCat("_main/client/trusted_application/test_data/", filename));
}

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

TEST(TrustedApplication, SuccessfulEcho) {
  absl::InitializeLog();
  HATS_ASSERT_OK_AND_ASSIGN(
      privacy_sandbox::crypto::TestEcKey client_authentication_key,
      privacy_sandbox::crypto::GenerateEcKeyForTest());

  std::string app_key;
  EXPECT_EQ(absl::HexStringToBytes(kAppKey, &app_key), true);

  std::vector<privacy_sandbox::key_manager::TestUserData> user_data;
  privacy_sandbox::key_manager::TestUserData test_user =
      privacy_sandbox::key_manager::TestUserData{
          .user_id = 1,
          .user_authentication_public_key =
              client_authentication_key.public_key,
          .key_id = kUserId,
          .secret = app_key,
          .public_key = "1-public-key",
      };
  user_data.push_back(test_user);

  std::string tvsPrimaryKeyBytes;
  EXPECT_EQ(absl::HexStringToBytes(kTvsPrimaryKey, &tvsPrimaryKeyBytes), true);

  // Startup TVS
  auto key_fetcher =
      std::make_unique<privacy_sandbox::key_manager::TestKeyFetcher>(
          tvsPrimaryKeyBytes, "", user_data);
  int tvs_listening_port = 7778;

  HATS_ASSERT_OK_AND_ASSIGN(std::string appraisal_policy_path,
                            GetRunfilePath(kAppraisalPolicy));

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<privacy_sandbox::tvs::PolicyFetcher> policy_fetcher,
      privacy_sandbox::tvs::PolicyFetcher::Create(appraisal_policy_path));

  HATS_ASSERT_OK_AND_ASSIGN(
      privacy_sandbox::tvs::AppraisalPolicies appraisal_policies,
      policy_fetcher->GetLatestNPolicies(/*n=*/5));

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<privacy_sandbox::tvs::TvsService> tvs_service,
      privacy_sandbox::tvs::TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = false,
          .accept_insecure_policies = true,
      }));

  LOG(INFO) << "Starting TVS server on port " << tvs_listening_port;

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder()
          .AddListeningPort(absl::StrCat("0.0.0.0:", tvs_listening_port),
                            grpc::InsecureServerCredentials())
          .RegisterService(tvs_service.get())
          .BuildAndStart();

  // Startup Launcher
  LOG(INFO) << "read configuration";

  HATS_ASSERT_OK_AND_ASSIGN(std::string launcher_config_path,
                            GetRunfilePath(kLauncherConfig));

  HATS_ASSERT_OK_AND_ASSIGN(privacy_sandbox::client::LauncherConfig config,
                            LoadConfig(launcher_config_path));

  HATS_ASSERT_OK_AND_ASSIGN(std::string system_bundle,
                            GetRunfilePath("system_bundle.tar"));

  config.mutable_cvm_config()->set_hats_system_bundle(system_bundle);

  HATS_ASSERT_OK_AND_ASSIGN(std::string runtime_bundle,
                            GetRunfilePath("runtime_bundle.tar"));
  config.mutable_cvm_config()->set_runc_runtime_bundle(runtime_bundle);
  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;
  HATS_ASSERT_OK_AND_ASSIGN(
      std::shared_ptr<grpc::Channel> tvs_channel,
      privacy_sandbox::tvs::CreateGrpcChannel(
          privacy_sandbox::tvs::CreateGrpcChannelOptions{
              .use_tls = false,
              .target = absl::StrCat("localhost:",
                                     std::to_string(tvs_listening_port)),
              .access_token = "",
          }));

  channel_map[0] = std::move(tvs_channel);

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<privacy_sandbox::client::HatsLauncher> launcher,
      privacy_sandbox::client::HatsLauncher::Create({
          .config = std::move(config),
          .tvs_authentication_key_bytes = std::string(
              client_authentication_key.private_key.GetStringView()),
          .private_key_wrapping_keys =
              privacy_sandbox::client::PrivateKeyWrappingKeys(),
          .tvs_channels = std::move(channel_map),
          .vmm_log_to_std = true,
      }));

  // Generate the log file randomly.
  HATS_EXPECT_OK(launcher->Start());

  // Now here we need to check if app is ready, if it is, start up app client
  // and talk to it.
  int counter = 6;
  while (!launcher->IsAppReady() && launcher->CheckStatus() && counter > 0) {
    std::cout << "Waiting for app to be ready" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    counter--;
  }
  EXPECT_EQ(launcher->CheckStatus(), true);

  privacy_sandbox::client::TrustedApplicationClient app_client =
      privacy_sandbox::client::TrustedApplicationClient(app_key, kUserId);

  HATS_ASSERT_OK_AND_ASSIGN(privacy_sandbox::client::DecryptedResponse response,
                            app_client.SendEcho());

  EXPECT_EQ(privacy_sandbox::client::kTestMessage,
            *response.mutable_response());
  std::cout << *response.mutable_response();
  launcher->Shutdown();
  tvs_server->Shutdown();
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
