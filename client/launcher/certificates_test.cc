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

#include "client/launcher/certificates.h"

#include <string>

#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "curl/curl.h"
#include "gmock/gmock-matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"

#include "httplib.h"
namespace privacy_sandbox::client {
namespace {
using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::_;
using ::testing::Exactly;
using ::testing::Return;

absl::StatusOr<std::string> GetVcek() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }

  absl::StatusOr<std::string> path =
      runfiles->Rlocation("_main/client/test_data/launcher/vcek");
  if (!path.ok()) {
    return path.status();
  }

  std::ifstream if_stream(*path, std::ifstream::binary);
  if (!if_stream.is_open()) {
    return absl::UnknownError(absl::StrCat("failed to open file ", *path));
  }

  std::string result;
  while (!if_stream.eof()) {
    std::string buffer;
    buffer.resize(1024);
    if_stream.read(buffer.data(), buffer.size());
    result += std::string(buffer.data(), if_stream.gcount());
  }

  return result;
}

TEST(Certificates, DownloadCertificateTest) {
  absl::StatusOr<std::string> vcek = GetVcek();
  ASSERT_THAT(vcek, IsOk());
  // Run a test HTTP server.
  httplib::Server server;
  server.Get("/vcek",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/vcek") {
                 response.set_content(*vcek, "application/octet-stream");
               }
             });
  std::thread server_thread([&] { server.listen("localhost", 8080); });
  absl::StatusOr<std::string> cert =
      DownloadCertificate("http://localhost:8080/vcek");
  server.stop();
  server_thread.join();
  EXPECT_THAT(cert, IsOkAndHolds(*vcek));
}
}  // namespace
}  // namespace privacy_sandbox::client
