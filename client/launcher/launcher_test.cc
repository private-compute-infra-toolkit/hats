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

#include "client/launcher/launcher.h"

#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "client/proto/launcher.grpc.pb.h"
#include "external/oak/proto/containers/interfaces.grpc.pb.h"
#include "external/oak/proto/containers/interfaces.pb.h"
#include "google/protobuf/empty.pb.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/create_channel.h"
#include "gtest/gtest.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace privacy_sandbox::client {
namespace {

using ::testing::HasSubstr;

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
      absl::StrCat("_main/client/test_data/launcher/", filename));
}

absl::StatusOr<LauncherConfig> ParseLauncherConfigFromFile(
    const std::string& runfile_path) {
  LauncherConfig config;
  std::ifstream if_stream(runfile_path);
  if (!if_stream.is_open())
    return absl::UnknownError(
        absl::StrCat("Cannot open file at '", runfile_path, "'"));
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  if (!google::protobuf::TextFormat::Parse(&istream, &config)) {
    return absl::UnknownError(
        absl::StrCat("Cannot parse proto from '", runfile_path, "'"));
  }
  return config;
}

TEST(HatsLauncher, Successful) {
  // Ensure that the folders are correctly generated and QEMU process is
  // correctly spawned.
  HATS_ASSERT_OK_AND_ASSIGN(
      std::string runfile_path,
      GetRunfilePath("launcher_config_port_forwarding.textproto"));
  HATS_ASSERT_OK_AND_ASSIGN(LauncherConfig config,
                            ParseLauncherConfigFromFile(runfile_path));

  HATS_ASSERT_OK_AND_ASSIGN(std::string system_bundle,
                            GetRunfilePath("system_bundle.tar"));
  config.mutable_cvm_config()->set_hats_system_bundle(system_bundle);

  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<HatsLauncher> launcher,
                            privacy_sandbox::client::HatsLauncher::Create({
                                .config = config,
                                .tvs_authentication_key_bytes = "test",
                            }));
  // Bind to no port so that it works in hermetic test.
  // In this mode, we can only use in process channel.
  std::thread launcher_thread([&] {
    HATS_ASSERT_OK(launcher->Start());
    launcher->Wait();
  });

  launcher->WaitUntilReady();
  // Ensure all GRPC services are up and running even though they may return bad
  // result.
  auto hats_stub = LauncherService::NewStub(
      grpc::CreateChannel(absl::StrCat("vsock:2:", launcher->GetVsockPort()),
                          grpc::InsecureChannelCredentials()));
  // Vsock is used for stage1 oak launcher to run.
  auto oak_stub = oak::containers::Launcher::NewStub(
      grpc::CreateChannel(absl::StrCat("vsock:2:", launcher->GetVsockPort()),
                          grpc::InsecureChannelCredentials()));
  // Simulated Stage 1 should get the system bundle image, which is empty in our
  // test.
  grpc::ClientContext context;
  std::unique_ptr<grpc::ClientReader<oak::containers::GetImageResponse>> reader(
      oak_stub->GetOakSystemImage(&context,
                                  google::protobuf::Empty::default_instance()));
  oak::containers::GetImageResponse response;
  std::string system_image;
  while (reader->Read(&response)) {
    system_image += response.image_chunk();
  }
  grpc::Status finish_status = reader->Finish();
  if ((finish_status.error_code() == grpc::StatusCode::UNAVAILABLE) &&
      (finish_status.error_message().ends_with("No such device"))) {
    std::string loopback_message =
        "Check if the kernel module vsock_loopback is installed, as it is "
        "needed for this test. You can load the module by running "
        "`sudo modprobe vsock_loopback`.";
    finish_status =
        grpc::Status(finish_status.error_code(),
                     finish_status.error_message() + "\n" + loopback_message,
                     finish_status.error_details());
  }
  HATS_EXPECT_OK_GRPC(finish_status);
  EXPECT_EQ(system_image, "");
  // Connect to the launcher service and check if everything is functional.
  launcher->Shutdown();
  launcher_thread.join();
  // Ensure that the QEMU is called with appropriate parameters.
  // In the test, we mock out the QEMU process with simple /usr/bin/echo to
  // capture the parameters.
  HATS_ASSERT_OK_AND_ASSIGN(std::string qemu_log,
                            launcher->GetQemuLogFilename());
  std::ifstream qemu_log_file(qemu_log);
  std::string qemu_log_content((std::istreambuf_iterator<char>(qemu_log_file)),
                               std::istreambuf_iterator<char>());
  EXPECT_THAT(qemu_log_content, HasSubstr("-enable-kvm"));
}

TEST(HatsLauncherTest, Unsuccessful) {
  HATS_ASSERT_OK_AND_ASSIGN(
      std::string runfile_path,
      GetRunfilePath("launcher_config_port_forwarding.textproto"));
  HATS_ASSERT_OK_AND_ASSIGN(LauncherConfig config,
                            ParseLauncherConfigFromFile(runfile_path));
  HATS_ASSERT_OK_AND_ASSIGN(std::string system_bundle,
                            GetRunfilePath("missing_bundle.tar"));
  config.mutable_cvm_config()->set_hats_system_bundle(system_bundle);

  HATS_EXPECT_STATUS(privacy_sandbox::client::HatsLauncher::Create({
                         .config = std::move(config),
                         .tvs_authentication_key_bytes = "test",
                     }),
                     absl::StatusCode::kInternal);
}
}  // namespace
}  // namespace privacy_sandbox::client
