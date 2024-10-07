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

#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock-matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"

#include "httplib.h"
#include "kernel-api-mock.h"

namespace privacy_sandbox::client {
namespace {
using ::testing::_;
using ::testing::Exactly;
using ::testing::Return;

absl::StatusOr<std::string> GetCertificate() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }

  std::string path =
      runfiles->Rlocation("_main/client/test_data/launcher/vcek");
  if (path.empty()) {
    return absl::UnknownError(
        "failed to locate file '_main/client/test_data/launcher/vcek'.");
  }

  std::ifstream if_stream(path, std::ifstream::binary);
  if (!if_stream.is_open()) {
    return absl::UnknownError(absl::StrCat("failed to open file ", path));
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

TEST(DownloadCertificate, Success) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string vcek, GetCertificate());

  // Run a test HTTP server.
  httplib::Server server;
  server.Get("/vcek",
             [&](const httplib::Request& request, httplib::Response& response) {
               if (request.method == "GET" && request.path == "/vcek") {
                 response.set_content(vcek, "application/octet-stream");
               }
             });

  int port = server.bind_to_any_port("0.0.0.0");
  std::thread server_thread([&] { server.listen_after_bind(); });
  // Wait for the server to start before sending requests otherwise we might
  // deadlock.
  server.wait_until_ready();
  absl::StatusOr<std::string> cert =
      DownloadCertificate(absl::StrCat("http://localhost:", port, "/vcek"));
  server.stop();
  server_thread.join();
  HATS_EXPECT_OK_AND_HOLDS(cert, vcek);
}

TEST(Certificates, GetCertificateUrlCpuFailure) {
  KernelApiMock api;
  // Invalid register value would result in failure.
  api.eax_ = 0xa10f;
  api.ebx_ = 0x40000000;
  api.ecx_ = 0x75c237ff;
  api.edx_ = 0x2fd3fbff;
  HATS_EXPECT_STATUS(GetCertificateUrl(api), absl::StatusCode::kUnknown);
}

TEST(Certificates, GetCertificateUrlTcbFailure) {
  KernelApiMock api;
  // Register values from real call to AMD EPYC Genoa B1 [Zen 4].
  api.eax_ = 0xa10f11;
  api.ebx_ = 0x40000000;
  api.ecx_ = 0x75c237ff;
  api.edx_ = 0x2fd3fbff;
  // real CPU ID for sev user get ID
  constexpr absl::string_view cpu_id =
      "d2421d976f95ce0ba849b7cc5c789122f1e59c77a037272c137ae4d188bb102adbc7c53d"
      "0302bff82a432c94a305dec7a7a270ceb19a10f04a83316c6486968d";
  std::string cpu_id_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(cpu_id, &cpu_id_bytes));
  ASSERT_EQ(cpu_id_bytes.size(), 64);
  for (size_t i = 0; i < 64; i++) {
    api.sev_user_get_id_socket1_[i] = static_cast<__u8>(cpu_id_bytes[i]);
  }
  api.sev_cmd_err_code_ = SEV_RET_INVALID_PLATFORM_STATE;
  api.reported_tcb_ = 0x3e0f000000000007;
  HATS_EXPECT_STATUS(GetCertificateUrl(api), absl::StatusCode::kUnknown);
}

TEST(Certificates, GetCertificateUrlSuccessful) {
  KernelApiMock api;
  // Register values from real call to AMD EPYC Genoa B1 [Zen 4].
  api.eax_ = 0xa10f11;
  api.ebx_ = 0x40000000;
  api.ecx_ = 0x75c237ff;
  api.edx_ = 0x2fd3fbff;
  // real CPU ID for sev user get ID
  constexpr absl::string_view cpu_id =
      "d2421d976f95ce0ba849b7cc5c789122f1e59c77a037272c137ae4d188bb102adbc7c53d"
      "0302bff82a432c94a305dec7a7a270ceb19a10f04a83316c6486968d";
  std::string cpu_id_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(cpu_id, &cpu_id_bytes));
  ASSERT_EQ(cpu_id_bytes.size(), 64);
  for (size_t i = 0; i < 64; i++) {
    api.sev_user_get_id_socket1_[i] = static_cast<__u8>(cpu_id_bytes[i]);
  }
  api.sev_cmd_err_code_ = SEV_RET_SUCCESS;
  api.reported_tcb_ = 0x3e0f000000000007;
  HATS_EXPECT_OK_AND_HOLDS(
      GetCertificateUrl(api),
      "https://kdsintf.amd.com/vcek/v1/Genoa/"
      "d2421d976f95ce0ba849b7cc5c789122f1e59c77a037272c137ae4d188bb102adbc7c53d"
      "0302bff82a432c94a305dec7a7a270ceb19a10f04a83316c6486968d"
      "?blSPL=07&teeSPL=00&snpSPL=15&ucodeSPL=62");
}
}  // namespace
}  // namespace privacy_sandbox::client
