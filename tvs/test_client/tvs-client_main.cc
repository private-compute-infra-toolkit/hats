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
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/strings/escaping.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/channel.h"
#include "proto/attestation/evidence.pb.h"
#include "status_macro/status_macros.h"
#include "tvs/credentials/credentials.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

ABSL_FLAG(std::string, tvs_address, "localhost:8081", "TVS server address.");
ABSL_FLAG(std::string, tvs_public_key, "",
          "TVS public key in hex format e.g. deadbeef");
ABSL_FLAG(bool, use_tls, false, "Whether to use TLS to connect to TVS or not.");
ABSL_FLAG(std::string, evidence_file, "",
          "File containing an oak evidence to be sent to TVS for validation");
ABSL_FLAG(std::string, tee_certificate_file, "",
          "File containing a tee certificate (vcek) - an endorsement from the "
          "vendor - to be sent along evidenced to TVS for validation");
ABSL_FLAG(std::string, application_signing_key, "",
          "Signing key in the application layer of the DICE certificate in hex "
          "format e.g. deadbeef. The key is used to sign the handshake hash "
          "and the evidence.");
ABSL_FLAG(std::string, access_token, "",
          "Access token to pass in the GRPC request. TLS needs to be enabled");
ABSL_FLAG(std::string, tvs_authentication_key, "",
          "Private key used to authenticate with TVS in hex format "
          "e.g. deadbeef");

namespace {

absl::StatusOr<oak::attestation::v1::Evidence> EvidenceFromFile(
    const std::string& file_path) {
  oak::attestation::v1::Evidence evidence;
  std::ifstream if_stream(file_path);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  if (!google::protobuf::TextFormat::Parse(&istream, &evidence)) {
    return absl::UnknownError(
        absl::StrCat("Cannot parse proto from '", file_path, "'"));
  }
  return evidence;
}

absl::StatusOr<std::string> ReadBinaryFile(const std::string& path) {
  std::ifstream if_stream(path);
  if (!if_stream.is_open()) {
    return absl::UnknownError(absl::StrCat("Cannot open file at '", path, "'"));
  }
  if_stream.seekg(0, std::ios::end);
  std::streampos file_size = if_stream.tellg();
  if_stream.seekg(0, std::ios::beg);
  std::string data;
  data.resize(file_size);
  if_stream.read(data.data(), file_size);
  if (!if_stream) {
    return absl::UnknownError(
        absl::StrCat("Cannot read from file at '", path, "'"));
  }
  return data;
}

absl::StatusOr<pcit::tvs::VerifyReportRequest> GetVerifyReportRequest(
    const std::string& evidence_file, const std::string& tee_certificate_file) {
  HATS_ASSIGN_OR_RETURN(oak::attestation::v1::Evidence evidence,
                        EvidenceFromFile(evidence_file));
  pcit::tvs::VerifyReportRequest request;
  *request.mutable_evidence() = std::move(evidence);
  HATS_ASSIGN_OR_RETURN(*request.mutable_tee_certificate(),
                        ReadBinaryFile(tee_certificate_file));
  return request;
}

}  // namespace

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  const std::string application_signing_key =
      absl::GetFlag(FLAGS_application_signing_key);
  if (application_signing_key.empty()) {
    LOG(ERROR) << "--application_signing_key cannot be empty.";
    return 1;
  }

  HATS_ASSIGN_OR_RETURN(
      pcit::tvs::VerifyReportRequest verify_report_request,
      GetVerifyReportRequest(absl::GetFlag(FLAGS_evidence_file),
                             absl::GetFlag(FLAGS_tee_certificate_file)),
      _.PrependWith("Couldn't create VerifyReportRequest: ").LogErrorAndExit());

  if (!absl::GetFlag(FLAGS_access_token).empty() &&
      !absl::GetFlag(FLAGS_use_tls)) {
    LOG(ERROR) << "TLS need to be enabled when passing access token.";
    return 1;
  }

  if (absl::GetFlag(FLAGS_tvs_authentication_key).empty()) {
    LOG(ERROR) << "--tvs_authentication_key cannot be empty.";
    return 1;
  }

  HATS_ASSIGN_OR_RETURN(
      std::shared_ptr<grpc::Channel> channel,
      pcit::tvs::CreateGrpcChannel({
          .use_tls = absl::GetFlag(FLAGS_use_tls),
          .target = absl::GetFlag(FLAGS_tvs_address),
          .access_token = absl::GetFlag(FLAGS_access_token),
      }),
      _.PrependWith("Error creating GRPC channel: ").LogErrorAndExit());

  const std::string tvs_address = absl::GetFlag(FLAGS_tvs_address);
  LOG(INFO) << "Creating TVS client to : " << tvs_address;
  HATS_ASSIGN_OR_RETURN(
      std::unique_ptr<pcit::tvs::TvsUntrustedClient> tvs_client,
      pcit::tvs::TvsUntrustedClient::CreateClient({
          .tvs_public_key = absl::GetFlag(FLAGS_tvs_public_key),
          .tvs_authentication_key = absl::GetFlag(FLAGS_tvs_authentication_key),
          .channel = std::move(channel),
      }),
      _.PrependWith("Couldn't create TVS client: ").LogErrorAndExit());
  HATS_ASSIGN_OR_RETURN(
      pcit::tvs::VerifyReportResponse response,
      tvs_client->VerifyReportAndGetSecrets(application_signing_key,
                                            verify_report_request),
      _.PrependWith("TVS rejected the report: ").LogErrorAndExit());

  for (const pcit::tvs::Secret& secret : response.secrets()) {
    std::cout << "Key id: " << secret.key_id() << std::endl;
    std::cout << "Public key: " << secret.public_key() << std::endl;
    std::string private_key_hex = absl::BytesToHexString(secret.private_key());
    std::cout << "Private key in hex format: " << private_key_hex << std::endl;
  }
  return 0;
}
