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
#include <optional>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "key_manager/key-fetcher.h"
#include "proto/attestation/reference_value.pb.h"
#include "tvs/untrusted_tvs/tvs-server.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");

namespace {

absl::StatusOr<int> GetPort() {
  int port = absl::GetFlag(FLAGS_port);
  if (port != -1) {
    return port;
  }
  // if port is -1, then take try environment variable.
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

  const std::string appraisal_policy_file =
      absl::GetFlag(FLAGS_appraisal_policy_file);
  if (appraisal_policy_file.empty()) {
    LOG(ERROR) << "--appraisal_policy_file cannot be empty.";
    return 1;
  }
  std::ifstream if_stream(appraisal_policy_file);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  oak::attestation::v1::ReferenceValues appraisal_policy;
  if (!google::protobuf::TextFormat::Parse(&istream, &appraisal_policy)) {
    LOG(ERROR) << "Failed to parse " << appraisal_policy_file;
    return 1;
  }

  std::unique_ptr<privacy_sandbox::key_manager::KeyFetcher> key_fetcher =
      privacy_sandbox::key_manager::KeyFetcher::Create();
  absl::StatusOr<std::string> primary_private_key =
      key_fetcher->GetPrimaryPrivateKey();
  if (!primary_private_key.ok()) {
    LOG(ERROR) << "Failed to fetch primary private key: "
               << primary_private_key.status();
    return 1;
  }

  absl::StatusOr<std::string> secondary_private_key =
      key_fetcher->GetSecondaryPrivateKey();
  if (!secondary_private_key.ok()) {
    LOG(WARNING) << "Failed to fetch secondary private key: "
                 << secondary_private_key.status();
  }

  absl::StatusOr<std::string> secret = key_fetcher->GetSecret(/*secret_id=*/"");
  if (!secret.ok()) {
    LOG(ERROR) << "Failed to fetch secret: " << secret.status();
    return 1;
  }

  absl::StatusOr<int> port = GetPort();
  if (!port.ok()) {
    LOG(ERROR) << "Cannot get server port " << port.status();
  }

  LOG(INFO) << "Starting TVS server on port " << port;
  privacy_sandbox::tvs::CreateAndStartTvsServer(
      privacy_sandbox::tvs::TvsServerOptions{
          .port = *std::move(port),
          .primary_private_key = *std::move(primary_private_key),
          .secondary_private_key = secondary_private_key.ok()
                                       ? *std::move(secondary_private_key)
                                       : "",
          .appraisal_policy = std::move(appraisal_policy),
          .secret = *std::move(secret),
      });
  return 0;
}
