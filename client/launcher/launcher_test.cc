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
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace privacy_sandbox::client {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;

absl::StatusOr<std::string> GetRunfilePath(absl::string_view filename) {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
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

absl::Status VerifyContent(absl::string_view full_runfile_path,
                           const std::vector<char>& want) {
  std::ifstream input(full_runfile_path.data(), std::ios::binary);
  std::vector<char> bytes((std::istreambuf_iterator<char>(input)),
                          (std::istreambuf_iterator<char>()));
  input.close();
  for (int i = 0; i < bytes.size(); ++i) {
    if (bytes[i] != want[i]) {
      return absl::InternalError(absl::StrFormat(
          "unexpected byte at loc %d  want %d got %d.", i, want[i], bytes[i]));
    }
  }
  return absl::OkStatus();
}

TEST(HatsLauncherTest, Successful) {
  absl::StatusOr<std::string> runfile_path =
      GetRunfilePath("launcher_config_port_forwarding.textproto");
  ASSERT_THAT(runfile_path, IsOk());
  absl::StatusOr<LauncherConfig> config =
      ParseLauncherConfigFromFile(*runfile_path);
  ASSERT_THAT(config, IsOk());
  absl::StatusOr<std::string> system_bundle =
      GetRunfilePath("system_bundle.tar");
  ASSERT_THAT(system_bundle, IsOk());
  (*config).mutable_cvm_config()->set_hats_system_bundle(*system_bundle);
  absl::StatusOr<std::unique_ptr<HatsLauncher>> launcher =
      privacy_sandbox::client::HatsLauncher::Create(*config);
  ASSERT_THAT(launcher, IsOk());
  EXPECT_THAT(VerifyContent((*launcher)->GetKernelBinaryPath(), {49, 10}),
              IsOk());
  EXPECT_THAT(VerifyContent((*launcher)->GetSystemImageTarXzPath(), {}),
              IsOk());
  EXPECT_THAT(VerifyContent((*launcher)->GetStage0BinaryPath(), {50, 49, 10}),
              IsOk());
  EXPECT_THAT(VerifyContent((*launcher)->GetInitrdCpioXzPath(), {97, 10}),
              IsOk());
}

TEST(HatsLauncherTest, Unsuccessful) {
  absl::StatusOr<std::string> runfile_path =
      GetRunfilePath("launcher_config_port_forwarding.textproto");
  ASSERT_THAT(runfile_path, IsOk());
  absl::StatusOr<LauncherConfig> config =
      ParseLauncherConfigFromFile(*runfile_path);
  ASSERT_THAT(config, IsOk());
  absl::StatusOr<std::string> system_bundle =
      GetRunfilePath("missing_bundle.tar");
  ASSERT_THAT(system_bundle, IsOk());
  (*config).mutable_cvm_config()->set_hats_system_bundle(*system_bundle);
  EXPECT_THAT(privacy_sandbox::client::HatsLauncher::Create(*config),
              StatusIs(absl::StatusCode::kInternal));
}
}  // namespace
}  // namespace privacy_sandbox::client
