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
#include <memory>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "key_manager/public-key-fetcher.h"
#include "public_key/public-key-server.h"
#include "status_macro/status_macros.h"

ABSL_FLAG(int, port, -1, "Port public key server listens to.");
ABSL_FLAG(std::string, aws_key_endpoint,
          "https://publickeyservice.pa.aws.privacysandboxservices.com/"
          ".well-known/protected-auction/v1/public-keys",
          "Address of the AWS public key instance");
ABSL_FLAG(std::string, gcp_key_endpoint,
          "https://publickeyservice.pa.gcp.privacysandboxservices.com/"
          ".well-known/protected-auction/v1/public-keys",
          "Address of the gcp public key instance");
ABSL_FLAG(std::string, bucket_name, "ps-hats-playground-public-keys",
          "Name of the Bucket to store the json file");

namespace {

absl::StatusOr<int> GetPort() {
  int port = absl::GetFlag(FLAGS_port);
  if (port != -1) {
    return port;
  }
  // if port is -1, then take try environment variable.
  // enviroment variable is used by Cloud Function.
  char* port_str = std::getenv("PORT");
  if (port_str == nullptr) {
    return absl::FailedPreconditionError(
        "Server port must be specified by flag or PORT environment variable");
  }

  if (!absl::SimpleAtoi(port_str, &port)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Cannot convert $PORT '", port_str, "' to integer"));
  }
  return port;
}
}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  HATS_ASSIGN_OR_RETURN(
      int port, GetPort(),
      _.PrependWith("Failed to get port from env or commandline: ")
          .LogErrorAndExit());

  std::unique_ptr<privacy_sandbox::key_manager::PublicKeyFetcher> key_fetcher =
      privacy_sandbox::key_manager::PublicKeyFetcher::Create();
  privacy_sandbox::public_key_service::CreateAndStartPublicKeyServer(
      {
          .port = port,
          .aws_key_endpoint = absl::GetFlag(FLAGS_aws_key_endpoint),
          .gcp_key_endpoint = absl::GetFlag(FLAGS_gcp_key_endpoint),
          .gcp_cloud_bucket_name = absl::GetFlag(FLAGS_bucket_name),
      },
      std::move(key_fetcher));
}
