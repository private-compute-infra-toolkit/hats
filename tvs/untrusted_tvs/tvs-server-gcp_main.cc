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
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "key_manager/gcp-kms-client.h"
#include "proto/attestation/reference_value.pb.h"
#include "tvs/untrusted_tvs/tvs-server.h"

ABSL_FLAG(int, port, -1, "Port TVS server listens to.");
// TODO(alwabel): implement a better key provisioning.
ABSL_FLAG(std::string, tvs_private_key, "",
          "Private key for NK-Noise handshake protocol.");
ABSL_FLAG(std::string, project_id, "", "Project ID.");
ABSL_FLAG(std::string, location_id, "", "Location ID.");
ABSL_FLAG(std::string, key_ring_id, "", "Key Ring ID.");
ABSL_FLAG(std::string, private_key_id, "", "CryptoKey ID.");
ABSL_FLAG(std::string, jwt_token_id, "", "JWT Token ID.");
ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");
<<<<<<< PATCH SET (f80140 Unwrapping JWT Token during TVS Boot)
ABSL_FLAG(std::string, token, "",
          "A token to be returned to client passing attestation validation. If "
          "empty returns a JWT token.");
=======
ABSL_FLAG(std::string, secret, "",
          "A secret to be returned to client passing attestation validation.");
>>>>>>> BASE      (51be59 Merge "Remove logic that generate jwt token as won't be need)

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

  absl::StatusOr<int> port = GetPort();
  if (!port.ok()) {
    LOG(ERROR) << "Cannot get server port " << port.status();
  }

  // Unwrapping key for TVS Private Key
  std::string private_key_id =
      absl::StrCat("projects/", absl::GetFlag(FLAGS_project_id), "/locations/",
                   absl::GetFlag(FLAGS_location_id), "/keyRings/",
                   absl::GetFlag(FLAGS_key_ring_id), "/cryptoKeys/",
                   absl::GetFlag(FLAGS_private_key_id));
  // Unwrapping key for JWT Token
  std::string jwt_token_id =
      absl::StrCat("projects/", absl::GetFlag(FLAGS_project_id), "/locations/",
                   absl::GetFlag(FLAGS_location_id), "/keyRings/",
                   absl::GetFlag(FLAGS_key_ring_id), "/cryptoKeys/",
                   absl::GetFlag(FLAGS_jwt_token_id));
  google::cloud::kms_v1::v2_25::KeyManagementServiceClient kms_client =
      google::cloud::kms_v1::KeyManagementServiceClient(
          google::cloud::kms_v1::MakeKeyManagementServiceConnection());
  privacy_sandbox::key_manager::GcpKmsClient client(kms_client);
  std::string encrypted_key;  // Encrypted key to be converted from HEX to Bytes
  if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_tvs_private_key),
                              &encrypted_key)) {
    LOG(ERROR) << "Failed to convert hex to binary";
    return 1;
  }
  absl::StatusOr<std::string> decrypted_key =
      client.DecryptData(private_key_id, encrypted_key);
  if (!decrypted_key.ok()) {
    LOG(ERROR) << "Failed to decrypt private key: " << decrypted_key.status();
  }
  std::string encrypted_token;
  if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_token), &encrypted_token)) {
    LOG(ERROR) << "Failed to convert hex to binary";
    return 1;
  }
  absl::StatusOr<std::string> decrypted_token =
      client.DecryptData(jwt_token_id, encrypted_token);
  if (!decrypted_token.ok()) {
    LOG(ERROR) << "Failed to decrypt JWT Token: " << decrypted_token.status();
  }

  LOG(INFO) << "Starting TVS server on port " << port;
  privacy_sandbox::tvs::CreateAndStartTvsServer(
      privacy_sandbox::tvs::TvsServerOptions{
          .port = *std::move(port),
          .tvs_private_key = std::move(decrypted_key.value()),
          .appraisal_policy = std::move(appraisal_policy),
<<<<<<< PATCH SET (f80140 Unwrapping JWT Token during TVS Boot)
          .token = std::move(decrypted_token.value()),
=======
          .secret = absl::GetFlag(FLAGS_secret),
>>>>>>> BASE      (51be59 Merge "Remove logic that generate jwt token as won't be need)
      });
  return 0;
}
