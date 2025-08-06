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

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/strings/escaping.h"
#include "crypto/aead-crypter.h"
#include "crypto/secret-data.h"
#include "crypto/secret_sharing/src/interface.rs.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/channel.h"
#include "status_macro/status_macros.h"
#include "tvs/credentials/credentials.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

using pcit::crypto::SecretData;

ABSL_FLAG(std::vector<std::string>, tvs_addresses,
          std::vector<std::string>({""}), "Ports TVS servers listens to.");
ABSL_FLAG(std::vector<std::string>, tvs_public_keys,
          std::vector<std::string>({""}),
          "Comma-separated List of TVS public key in hex format e.g. deadbeef");

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
ABSL_FLAG(std::string, user_dek, "",
          "Private key used to authenticate with TVS in hex format "
          "e.g. deadbeef");
ABSL_FLAG(
    std::string, share_split_type, "SHAMIR",
    "Describe the type of way to recover the split shares. Valid values are: "
    "SHAMIR, XOR");

rust::Slice<const std::uint8_t> StringToRustSlice(const std::string& str) {
  return rust::Slice<const std::uint8_t>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

std::string RustVecToString(const rust::Vec<std::uint8_t>& vec) {
  return std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
}

rust::Vec<rust::String> StringVecToRustVec(
    const std::vector<std::string>& arr) {
  rust::Vec<rust::String> emp;
  for (const std::string& s : arr) {
    emp.push_back(rust::String(s));
  }
  return emp;
}

// Stores public key and corresponding private key shares to be resassembled
struct KeyShares {
  std::string public_key;
  std::vector<std::string> secret_shares;
};

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
  pcit::tvs::VerifyReportRequest verify_report_request;
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
  std::vector<std::string> tvs_addresses = absl::GetFlag(FLAGS_tvs_addresses);
  std::vector<std::string> tvs_public_keys =
      absl::GetFlag(FLAGS_tvs_public_keys);
  // Here we are storing the public key, and associated key shares, indexed by
  // key_id
  std::unordered_map<std::string, KeyShares> keys;
  for (size_t i = 0; i < tvs_addresses.size(); i++) {
    HATS_ASSIGN_OR_RETURN(
        std::shared_ptr<grpc::Channel> channel,
        pcit::tvs::CreateGrpcChannel({
            .use_tls = absl::GetFlag(FLAGS_use_tls),
            .target = tvs_addresses[i],
            .access_token = absl::GetFlag(FLAGS_access_token),
        }),
        _.PrependWith(absl::StrCat("Error creating GRPC channel to",
                                   tvs_addresses[i], ": "))
            .LogErrorAndExit());

    HATS_ASSIGN_OR_RETURN(
        std::unique_ptr<pcit::tvs::TvsUntrustedClient> tvs_client,
        pcit::tvs::TvsUntrustedClient::CreateClient({
            .tvs_public_key = tvs_public_keys[i],
            .tvs_authentication_key =
                absl::GetFlag(FLAGS_tvs_authentication_key),
            .channel = channel,
        }),
        _.PrependWith(absl::StrCat("Couldn't create TVS client for ",
                                   tvs_addresses[i], ": "))
            .LogErrorAndExit());
    HATS_ASSIGN_OR_RETURN(
        pcit::tvs::VerifyReportResponse response,
        tvs_client->VerifyReportAndGetSecrets(application_signing_key,
                                              verify_report_request),
        _.PrependWith("TVS rejected the report: ").LogErrorAndExit());
    for (const pcit::tvs::Secret& secret : response.secrets()) {
      KeyShares& shares = keys[secret.key_id()];
      shares.public_key = secret.public_key();
      shares.secret_shares.push_back(secret.private_key());
    }
  }
  for (const auto& [key_id, shared_secret] : keys) {
    absl::string_view share_split_type = absl::GetFlag(FLAGS_share_split_type);
    rust::Vec<uint8_t> recovered_secret;
    if (share_split_type == "XOR") {
      HATS_ASSIGN_OR_RETURN(
          recovered_secret,
          pcit::crypto::XorRecoverSecret(
              StringVecToRustVec(shared_secret.secret_shares),
              tvs_addresses.size()),
          _.PrependWith("Failed to recover XOR secret: ").LogErrorAndExit());
    } else if (share_split_type == "SHAMIR") {
      HATS_ASSIGN_OR_RETURN(
          recovered_secret,
          pcit::crypto::ShamirRecoverSecret(
              StringVecToRustVec(shared_secret.secret_shares),
              tvs_addresses.size(),
              std::max(tvs_addresses.size() - 1, static_cast<size_t>(2))),
          _.PrependWith("Failed to recover SHAMIR secret: ").LogErrorAndExit());
    } else {
      LOG(ERROR) << absl::StrCat("Unknown split type '", share_split_type, "'")
                 << std::endl;
      return 1;
    }

    std::string bytes;
    if (absl::GetFlag(FLAGS_user_dek) != "") {
      std::string wrapped_key = RustVecToString(recovered_secret);
      SecretData wrapped_secret = SecretData(wrapped_key);
      std::string dec;
      if (!absl::HexStringToBytes(absl::GetFlag(FLAGS_user_dek), &dec)) {
        LOG(ERROR) << "user_dek must be a 32 byte key in hex string format"
                   << std::endl;
        return 1;
      }
      SecretData dek = SecretData(dec);
      HATS_ASSIGN_OR_RETURN(
          SecretData unwrapped_key,
          pcit::crypto::Decrypt(dek, wrapped_secret, pcit::crypto::kSecretAd),
          _.PrependWith("Invalid private key recovered").LogErrorAndExit());
      bytes = unwrapped_key.GetStringView();
    } else {
      bytes = RustVecToString(recovered_secret);
    }
    std::string priv_key_hex = absl::BytesToHexString(bytes);
    std::cout << "Key id: " << key_id << std::endl;
    std::cout << "Public key: " << shared_secret.public_key << std::endl;
    std::cout << "Private key: " << priv_key_hex << std::endl;
  }
  return 0;
}
