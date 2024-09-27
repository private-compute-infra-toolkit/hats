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
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/channel.h"
#include "tvs/credentials/credentials.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

ABSL_FLAG(std::string, tvs_address, "localhost:8081", "TVS server address.");
ABSL_FLAG(std::string, tvs_public_key, "",
          "TVS public key in hex format e.g. deadbeef");
ABSL_FLAG(bool, use_tls, false, "Whether to use TLS to connect to TVS or not.");
ABSL_FLAG(std::string, verify_report_request_file, "",
          "File containing a VerifyReportRequest to be sent to TVS for "
          "validation");
ABSL_FLAG(std::string, application_signing_key, "",
          "Signing key in the application layer of the DICE certificate in hex "
          "format e.g. deadbeef. The key is used to sign the handshake hash "
          "and the evidence.");
ABSL_FLAG(std::string, access_token, "",
          "Access token to pass in the GRPC request. TLS needs to be enabled");
ABSL_FLAG(std::string, tvs_authentication_key, "",
          "Private key used to authenticate with TVS in hex format "
          "e.g. deadbeef");

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  const std::string verify_report_request_file =
      absl::GetFlag(FLAGS_verify_report_request_file);
  if (verify_report_request_file.empty()) {
    LOG(ERROR) << "--verify_report_request_file cannot be empty.";
    return 1;
  }

  const std::string application_signing_key =
      absl::GetFlag(FLAGS_application_signing_key);
  if (application_signing_key.empty()) {
    LOG(ERROR) << "--application_signing_key cannot be empty.";
    return 1;
  }
  std::ifstream if_stream(verify_report_request_file);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  privacy_sandbox::tvs::VerifyReportRequest verify_report_request;
  if (!google::protobuf::TextFormat::Parse(&istream, &verify_report_request)) {
    LOG(ERROR) << "Failed to parse " << verify_report_request_file;
    return 1;
  }

  if (!absl::GetFlag(FLAGS_access_token).empty() &&
      !absl::GetFlag(FLAGS_use_tls)) {
    LOG(ERROR) << "TLS need to be enabled when passing access token.";
    return 1;
  }

  if (absl::GetFlag(FLAGS_tvs_authentication_key).empty()) {
    LOG(ERROR) << "--tvs_authentication_key cannot be empty.";
    return 1;
  }

  absl::StatusOr<std::shared_ptr<grpc::Channel>> channel =
      privacy_sandbox::tvs::CreateGrpcChannel({
          .use_tls = absl::GetFlag(FLAGS_use_tls),
          .target = absl::GetFlag(FLAGS_tvs_address),
          .access_token = absl::GetFlag(FLAGS_access_token),
      });
  if (!channel.ok()) {
    LOG(ERROR) << "Error creating GRPC channel: " << channel;
    return 1;
  }

  const std::string tvs_address = absl::GetFlag(FLAGS_tvs_address);
  LOG(INFO) << "Creating TVS client to : " << tvs_address;
  absl::StatusOr<std::unique_ptr<privacy_sandbox::tvs::TvsUntrustedClient>>
      tvs_client = privacy_sandbox::tvs::TvsUntrustedClient::CreateClient({
          .tvs_public_key = absl::GetFlag(FLAGS_tvs_public_key),
          .tvs_authentication_key = absl::GetFlag(FLAGS_tvs_authentication_key),
          .channel = std::move(channel).value(),
      });
  if (!tvs_client.ok()) {
    LOG(ERROR) << "Couldn't create TVS client: " << tvs_client.status();
    return 1;
  }
  absl::StatusOr<privacy_sandbox::tvs::VerifyReportResponse> response =
      (*tvs_client)
          ->VerifyReportAndGetSecrets(application_signing_key,
                                      verify_report_request);
  if (!response.ok()) {
    std::cout << "TVS rejected the report: " << response.status() << std::endl;
  }

  for (const privacy_sandbox::tvs::Secret& secret : response->secrets()) {
    std::cout << "Key id: " << secret.key_id() << std::endl;
    std::cout << "Public key: " << secret.public_key() << std::endl;
    if (absl::StatusOr<std::string> private_key_hex =
            absl::BytesToHexString(secret.private_key());
        private_key_hex.ok()) {
      std::cout << "Prvate key in hex format: " << private_key_hex << std::endl;
    } else {
      std::cout << "Failed to convert private key to hex; token in bytes is: "
                << secret.private_key() << std::endl;
    }
  }
  return 0;
}
