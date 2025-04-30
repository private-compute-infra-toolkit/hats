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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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
#include "absl/strings/string_view.h"
#include "client/launcher/launcher.h"
#include "client/proto/launcher_config.pb.h"
#include "client/proto/trusted_service.pb.h"
#include "client/trusted_application/client/trusted_application_client.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "crypto/secret_sharing/src/interface.rs.h"
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

namespace privacy_sandbox::client {
namespace {

using ::testing::SizeIs;

constexpr absl::string_view kKeyId = "64";
constexpr absl::string_view kLauncherConfig = "launcher_config.txtpb";
constexpr absl::string_view kAppraisalPolicy = "appraisal_policy.txtpb";
constexpr absl::string_view kFirstTvsPrimaryKey =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr absl::string_view kSecondTvsPrimaryKey =
    "0000000000000000000000000000000000000000000000000000000000000002";
constexpr absl::string_view kThirdTvsPrimaryKey =
    "0000000000000000000000000000000000000000000000000000000000000003";

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

absl::StatusOr<LauncherConfig> LoadConfig(absl::string_view path) {
  std::ifstream file(path.data());
  if (!file.is_open()) {
    return absl::InvalidArgumentError(
        absl::StrCat("failed to open file '", path, "'"));
  }
  std::string raw_config((std::istreambuf_iterator<char>(file)),
                         (std::istreambuf_iterator<char>()));
  file.close();
  LauncherConfig config;
  if (!google::protobuf::TextFormat::ParseFromString(raw_config, &config)) {
    return absl::InvalidArgumentError(
        absl::StrCat("invalid textproto message at path '", path, "'"));
  }

  return config;
}

// Holds an IP port and socket file descriptor.
class IPPort {
 public:
  explicit IPPort(int port, int socket_fd)
      : port_(port), socket_fd_(socket_fd) {}
  IPPort(const IPPort& arg) = delete;
  IPPort(IPPort&& arg) = delete;
  IPPort& operator=(const IPPort& arg) = delete;
  IPPort& operator=(IPPort&& arg) = delete;

  ~IPPort() { close(socket_fd_); }

  int port() const { return port_; }

 private:
  int port_;
  int socket_fd_;
};

absl::StatusOr<std::unique_ptr<IPPort>> GetUnusedPort() {
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    return absl::UnknownError("Failed to open socket.");
  }

  int reuse = 1;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    close(socket_fd);
    return absl::UnknownError("Failed to set socket option.");
  }

  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  // Assign zero to tell the OS to assign a port for us.
  address.sin_port = 0;
  if (bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
    close(socket_fd);
    return absl::UnknownError("Failed to bind socket.");
  }

  struct sockaddr_in actual_addr;
  socklen_t addrlen = sizeof(actual_addr);
  if (getsockname(socket_fd, (struct sockaddr*)&actual_addr, &addrlen) == -1) {
    close(socket_fd);
    return absl::UnknownError("Failed to get socket name.");
  }
  return std::make_unique<IPPort>(ntohs(actual_addr.sin_port), socket_fd);
}

absl::StatusOr<std::unique_ptr<tvs::TvsService>> CreateTvs(
    absl::string_view tvs_primary_private_key,
    const std::vector<key_manager::TestUserData>& test_user_data) {
  std::string tvsPrimaryKeyBytes;
  if (!absl::HexStringToBytes(tvs_primary_private_key, &tvsPrimaryKeyBytes)) {
    return absl::FailedPreconditionError(
        "Failed to convert TVS Primary Key to Hex");
  }

  HATS_ASSIGN_OR_RETURN(std::string appraisal_policy_path,
                        GetRunfilePath(kAppraisalPolicy));
  HATS_ASSIGN_OR_RETURN(std::unique_ptr<tvs::PolicyFetcher> policy_fetcher,
                        tvs::PolicyFetcher::Create(appraisal_policy_path));

  HATS_ASSIGN_OR_RETURN(tvs::AppraisalPolicies appraisal_policies,
                        policy_fetcher->GetLatestNPolicies(/*n=*/100));

  // Startup TVS
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvsPrimaryKeyBytes, /*secondary_private_key=*/"", test_user_data);

  return tvs::TvsService::Create({
      .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
          tvsPrimaryKeyBytes, /*secondary_private_key=*/"", test_user_data),
      .appraisal_policies = std::move(appraisal_policies),
      .enable_policy_signature = false,
      .accept_insecure_policies = true,
  });
}

struct TestTvs {
  std::unique_ptr<IPPort> ip_port;
  std::unique_ptr<tvs::TvsService> tvs_service;
  std::unique_ptr<grpc::Server> tvs_server;
};

absl::StatusOr<TestTvs> CreateAndStartTestTvs(
    absl::string_view tvs_primary_private_key,
    const std::vector<key_manager::TestUserData>& test_user_data) {
  HATS_ASSIGN_OR_RETURN(std::unique_ptr<tvs::TvsService> tvs_service,
                        CreateTvs(tvs_primary_private_key, test_user_data));

  HATS_ASSIGN_OR_RETURN(std::unique_ptr<IPPort> tvs_port, GetUnusedPort());

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder()
          .AddListeningPort(absl::StrCat("0.0.0.0:", tvs_port->port()),
                            grpc::InsecureServerCredentials())
          .RegisterService(tvs_service.get())
          .BuildAndStart();

  return TestTvs{
      .ip_port = std::move(tvs_port),
      .tvs_service = std::move(tvs_service),
      .tvs_server = std::move(tvs_server),
  };
}

struct TestLauncher {
  std::unique_ptr<IPPort> ip_port;
  std::unique_ptr<client::HatsLauncher> launcher;
};

absl::StatusOr<TestLauncher> CreateAndStartTestLauncher(
    const std::vector<int>& tvs_ports, absl::string_view system_bundle_name,
    absl::string_view client_authentication_private_key) {
  HATS_ASSIGN_OR_RETURN(std::string launcher_config_path,
                        GetRunfilePath(kLauncherConfig));

  HATS_ASSIGN_OR_RETURN(client::LauncherConfig config,
                        LoadConfig(launcher_config_path));

  HATS_ASSIGN_OR_RETURN(std::unique_ptr<IPPort> enclave_proxy_ip_port,
                        GetUnusedPort());
  privacy_sandbox::client::NetworkConfig& network_config =
      *config.mutable_cvm_config()->mutable_network_config();
  network_config.mutable_inbound_only()->set_host_enclave_app_proxy_port(
      enclave_proxy_ip_port->port());

  HATS_ASSIGN_OR_RETURN(std::string system_bundle,
                        GetRunfilePath(system_bundle_name));

  config.mutable_cvm_config()->set_hats_system_bundle(system_bundle);

  HATS_ASSIGN_OR_RETURN(std::string runtime_bundle,
                        GetRunfilePath("runtime_bundle.tar"));
  config.mutable_cvm_config()->set_runc_runtime_bundle(runtime_bundle);

  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;

  for (size_t i = 0; i < tvs_ports.size(); ++i) {
    HATS_ASSIGN_OR_RETURN(
        std::shared_ptr<grpc::Channel> tvs_channel,
        tvs::CreateGrpcChannel(tvs::CreateGrpcChannelOptions{
            .use_tls = false,
            .target = absl::StrCat("localhost:", tvs_ports[i]),
        }));
    channel_map[i] = std::move(tvs_channel);
  }
  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<client::HatsLauncher> launcher,
      client::HatsLauncher::Create({
          .config = std::move(config),
          .tvs_authentication_key_bytes =
              std::string(client_authentication_private_key),
          .private_key_wrapping_keys = client::PrivateKeyWrappingKeys(),
          .tvs_channels = std::move(channel_map),
          .vmm_log_to_std = true,
      }));

  // Generate the log file randomly.
  HATS_RETURN_IF_ERROR(launcher->Start());

  return TestLauncher{
      .ip_port = std::move(enclave_proxy_ip_port),
      .launcher = std::move(launcher),
  };
}

absl::Status WaitForApp(const HatsLauncher& launcher) {
  // Now here we need to check if app is ready, if it is, start up app client
  // and talk to it.
  int counter = 10;
  while (!launcher.IsAppReady() && launcher.CheckStatus() && counter > 0) {
    std::cout << "Waiting for app to be ready" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    counter--;
  }

  if (!launcher.CheckStatus()) {
    return absl::FailedPreconditionError("Launcher failed to start.");
  }
  if (!launcher.IsAppReady()) {
    return absl::FailedPreconditionError("App is not ready.");
  }

  return absl::OkStatus();
}

TEST(TrustedApplication, EchoSingleTvs) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());
  crypto::SecretData app_key = crypto::RandomAeadKey();

  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs,
      CreateAndStartTestTvs(kFirstTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = std::string(app_key.GetStringView()),
                                .public_key = "1-public-key",
                            }}));
  LOG(INFO) << "TVS server is listening on port: " << test_tvs.ip_port->port();

  constexpr absl::string_view kSystemBundleName =
      "system_bundle_test_single.tar";
  HATS_ASSERT_OK_AND_ASSIGN(
      TestLauncher test_launcher,
      CreateAndStartTestLauncher(
          /*tvs_ports=*/{test_tvs.ip_port->port()}, kSystemBundleName,
          client_authentication_key.private_key.GetStringView()));

  HATS_ASSERT_OK(WaitForApp(*test_launcher.launcher));

  TrustedApplicationClient app_client(
      absl::StrCat("localhost:", test_launcher.ip_port->port()),
      app_key.GetStringView(), kKeyId);

  HATS_ASSERT_OK_AND_ASSIGN(DecryptedResponse response, app_client.SendEcho());

  EXPECT_EQ(*response.mutable_response(), kTestMessage);
  std::cout << *response.mutable_response();

  test_launcher.launcher->Shutdown();
  test_tvs.tvs_server->Shutdown();
}

TEST(TrustedApplication, EchoXor2Tvs) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());
  crypto::SecretData app_key = crypto::RandomAeadKey();

  HATS_ASSERT_OK_AND_ASSIGN(
      rust::Vec<rust::String> shares,
      privacy_sandbox::crypto::XorSplitSecret(
          rust::Slice<const std::uint8_t>(app_key.GetData(), app_key.GetSize()),
          /*numshares=*/2));

  ASSERT_THAT(shares, SizeIs(2));
  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs1,
      CreateAndStartTestTvs(kFirstTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = static_cast<std::string>(shares[0]),
                                .public_key = "1-public-key",
                            }}));

  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs2,
      CreateAndStartTestTvs(kSecondTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = static_cast<std::string>(shares[1]),
                                .public_key = "1-public-key",
                            }}));

  LOG(INFO) << "TVS servers are listening on ports: "
            << test_tvs1.ip_port->port() << ", " << test_tvs2.ip_port->port();

  constexpr absl::string_view kSystemBundleName =
      "system_bundle_test_xor_2.tar";
  HATS_ASSERT_OK_AND_ASSIGN(
      TestLauncher test_launcher,
      CreateAndStartTestLauncher(
          /*tvs_ports=*/{test_tvs1.ip_port->port(), test_tvs2.ip_port->port()},
          kSystemBundleName,
          client_authentication_key.private_key.GetStringView()));

  HATS_ASSERT_OK(WaitForApp(*test_launcher.launcher));

  TrustedApplicationClient app_client(
      absl::StrCat("localhost:", test_launcher.ip_port->port()),
      app_key.GetStringView(), kKeyId);

  HATS_ASSERT_OK_AND_ASSIGN(DecryptedResponse response, app_client.SendEcho());

  EXPECT_EQ(*response.mutable_response(), kTestMessage);
  std::cout << *response.mutable_response();

  test_launcher.launcher->Shutdown();
  test_tvs1.tvs_server->Shutdown();
  test_tvs2.tvs_server->Shutdown();
}

TEST(TrustedApplication, EchoShmir2Of3Tvs) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());
  crypto::SecretData app_key = crypto::RandomAeadKey();

  HATS_ASSERT_OK_AND_ASSIGN(
      rust::Vec<rust::String> shares,
      privacy_sandbox::crypto::ShamirSplitSecret(
          rust::Slice<const std::uint8_t>(app_key.GetData(), app_key.GetSize()),
          /*numshares=*/3, /*threshold=*/2));

  ASSERT_THAT(shares, SizeIs(3));
  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs1,
      CreateAndStartTestTvs(kFirstTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = static_cast<std::string>(shares[0]),
                                .public_key = "1-public-key",
                            }}));

  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs2,
      CreateAndStartTestTvs(kSecondTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = static_cast<std::string>(shares[1]),
                                .public_key = "1-public-key",
                            }}));

  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs3,
      CreateAndStartTestTvs(kThirdTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = static_cast<std::string>(shares[2]),
                                .public_key = "1-public-key",
                            }}));
  LOG(INFO) << "TVS servers are listening on ports: "
            << test_tvs1.ip_port->port() << ", " << test_tvs2.ip_port->port()
            << ", " << test_tvs3.ip_port->port();

  constexpr absl::string_view kSystemBundleName =
      "system_bundle_test_shamir_2_of_3.tar";
  HATS_ASSERT_OK_AND_ASSIGN(
      TestLauncher test_launcher,
      CreateAndStartTestLauncher(
          /*tvs_ports=*/{test_tvs1.ip_port->port(), test_tvs2.ip_port->port(),
                         test_tvs3.ip_port->port()},
          kSystemBundleName,
          client_authentication_key.private_key.GetStringView()));

  HATS_ASSERT_OK(WaitForApp(*test_launcher.launcher));

  TrustedApplicationClient app_client(
      absl::StrCat("localhost:", test_launcher.ip_port->port()),
      app_key.GetStringView(), kKeyId);

  HATS_ASSERT_OK_AND_ASSIGN(DecryptedResponse response, app_client.SendEcho());

  EXPECT_EQ(*response.mutable_response(), kTestMessage);
  std::cout << *response.mutable_response();

  test_launcher.launcher->Shutdown();
  test_tvs1.tvs_server->Shutdown();
  test_tvs2.tvs_server->Shutdown();
  test_tvs3.tvs_server->Shutdown();
}

// Test periodic TVS heart-beat. In this test, the TVS updates the client key,
// and the orchestrator checks every 1 second with the TVS.
TEST(TrustedApplication, EchoSingleTvsUpdate) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());
  crypto::SecretData app_key1 = crypto::RandomAeadKey();

  constexpr absl::string_view kTvsPrimaryKey =
      "f664b3224ff336ca83923a730a8063c264746e76496334fa398fbbee1b630ab4";
  HATS_ASSERT_OK_AND_ASSIGN(
      TestTvs test_tvs,
      CreateAndStartTestTvs(kTvsPrimaryKey,
                            /*test_user_data=*/{key_manager::TestUserData{
                                .user_id = "1",
                                .user_authentication_public_key =
                                    client_authentication_key.public_key,
                                .key_id = std::string(kKeyId),
                                .secret = std::string(app_key1.GetStringView()),
                                .public_key = "1-public-key",
                            }}));
  LOG(INFO) << "TVS server is listening on port: " << test_tvs.ip_port->port();

  constexpr absl::string_view kSystemBundleName =
      "system_bundle_test_single_1sec_heartbeat.tar";
  HATS_ASSERT_OK_AND_ASSIGN(
      TestLauncher test_launcher,
      CreateAndStartTestLauncher(
          /*tvs_ports=*/{test_tvs.ip_port->port()}, kSystemBundleName,
          client_authentication_key.private_key.GetStringView()));

  HATS_ASSERT_OK(WaitForApp(*test_launcher.launcher));

  {
    TrustedApplicationClient app_client(
        absl::StrCat("localhost:", test_launcher.ip_port->port()),
        app_key1.GetStringView(), kKeyId);

    HATS_ASSERT_OK_AND_ASSIGN(DecryptedResponse response,
                              app_client.SendEcho());

    EXPECT_EQ(*response.mutable_response(), kTestMessage);
    std::cout << *response.mutable_response();
  }

  test_tvs.tvs_server->Shutdown();

  // Now start another TVS server and give it another key.
  crypto::SecretData app_key2 = crypto::RandomAeadKey();
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service,
      CreateTvs(kTvsPrimaryKey,
                /*test_user_data=*/{key_manager::TestUserData{
                    .user_id = "1",
                    .user_authentication_public_key =
                        client_authentication_key.public_key,
                    .key_id = "2",
                    .secret = std::string(app_key2.GetStringView()),
                    .public_key = "1-public-key",
                }}));
  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder()
          .AddListeningPort(absl::StrCat("0.0.0.0:", test_tvs.ip_port->port()),
                            grpc::InsecureServerCredentials())
          .RegisterService(tvs_service.get())
          .BuildAndStart();

  // Sleep for 5 seconds (Orchestrator pulls every second).
  std::this_thread::sleep_for(std::chrono::seconds(5));

  // Send the request again using a different key.
  {
    TrustedApplicationClient app_client(
        absl::StrCat("localhost:", test_launcher.ip_port->port()),
        app_key2.GetStringView(), /*key_id=*/"2");

    HATS_ASSERT_OK_AND_ASSIGN(DecryptedResponse response,
                              app_client.SendEcho());

    EXPECT_EQ(*response.mutable_response(), kTestMessage);
    std::cout << *response.mutable_response();
  }

  tvs_server->Shutdown();
  test_launcher.launcher->Shutdown();
}

}  // namespace
}  // namespace privacy_sandbox::client

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  // Tell TVS to be more verbose.
  if (setenv("RUST_LOG", "debug", /*overwrite=*/1) != 0) {
    LOG(WARNING) << "Failed to set RUST_LOG=debug";
  }
  return RUN_ALL_TESTS();
}
