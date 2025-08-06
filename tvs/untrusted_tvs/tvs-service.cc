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

#include "tvs/untrusted_tvs/tvs-service.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "status_macro/status_macros.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace pcit::tvs {

namespace {

rust::Slice<const std::uint8_t> StringToRustSlice(const std::string& str) {
  return rust::Slice<const std::uint8_t>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

std::string RustVecToString(const rust::Vec<std::uint8_t>& vec) {
  return std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
}

// Create a new session by:
// 1. Pass the requester's secrets to the enclave. The client public key is
// parsed from the request, `key_fetcher` is queried to get the user id and the
// secrets for that users. The user id and secrets are passed to the enclave.
// 2. Pass the message to the enclave so that the handshake is performed.
// Note that the secrets will not be returned to the client if the user failed
// to prove that it posses the private part of the provided public key or did
// not provide acceptable attestation report. The function returns session id
// along with the message to the client. The untrusted TVS keeps the session id,
// and attach
/// it to all messages from the same streaming gRRPC session.
// This is so that the enclave knows that the messages belong to the
// same session.
absl::StatusOr<CreateSessionResult> CreateSession(
    const OpaqueMessage& request, key_manager::KeyFetcher& key_fetcher,
    EnclaveClient& client) {
  // Extract client public key from the request.
  AttestReportRequest attest_report_request;
  if (!attest_report_request.ParseFromString(request.binary_message())) {
    return absl::InvalidArgumentError(
        "Failed to de-serialize (decode) request proto.");
  }
  if (!attest_report_request.has_init_session_request()) {
    return absl::InvalidArgumentError(
        "Request does not have InitSessionRequest field set.");
  }
  const InitSessionRequest& init_session_request =
      attest_report_request.init_session_request();

  // Fetch user id registered for the client public key.
  HATS_ASSIGN_OR_RETURN(std::string user_id,
                        key_fetcher.UserIdForAuthenticationKey(
                            init_session_request.client_public_key()));
  // Fetch secrets for `user_id`.
  HATS_ASSIGN_OR_RETURN(std::vector<key_manager::Secret> secrets,
                        key_fetcher.GetSecretsForUserId(user_id));

  // Convert `secrets` to a serialized `VerifyReportResponse` to be passed to
  // the enclave.
  std::string serialized_response;
  {
    VerifyReportResponse response;
    // Use non-const to enable effective use of std::move().
    for (key_manager::Secret& secret : secrets) {
      Secret& tvs_secret = *response.add_secrets();
      *tvs_secret.mutable_key_id() = std::move(secret.key_id);
      *tvs_secret.mutable_public_key() = std::move(secret.public_key);
      *tvs_secret.mutable_private_key() = std::move(secret.private_key);
    }
    serialized_response = response.SerializeAsString();
  }

  // Pass the secret to the enclave.
  HATS_RETURN_IF_ERROR(client.RegisterOrUpdateUser(
      StringToRustSlice(user_id),
      StringToRustSlice(init_session_request.client_public_key()),
      StringToRustSlice(serialized_response)));

  // Finally create a session.
  return client.CreateSession(StringToRustSlice(request.binary_message()));
}

// Terminate a session and log the error out. We do not return the error
// as if the request was successful then the client would have already received
// the result and if the request was not successful, we would already return
// them an error. Failure to terminate the session indicate a problem in the
// server. (eventually the server would stop accepting requests). The client
// cannot do anything so we do not return an error.
void TerminateSession(rust::Slice<const uint8_t> session_id,
                      EnclaveClient& client) {
  if (absl::Status status = client.TerminateSession(session_id); !status.ok()) {
    LOG(ERROR) << "Failed to terminate session";
  }
}

}  // namespace

TvsService::TvsService(rust::Box<Launcher> launcher,
                       std::unique_ptr<key_manager::KeyFetcher> key_fetcher)
    : launcher_(std::move(launcher)), key_fetcher_(std::move(key_fetcher)) {}

absl::StatusOr<std::unique_ptr<TvsService>> TvsService::Create(
    Options options) {
  HATS_ASSIGN_OR_RETURN(rust::Box<Launcher> launcher,
                        pcit::tvs::NewLauncher({
                            .vmm_binary = options.vmm_binary,
                            .bios_binary = options.bios_binary,
                            .kernel = options.kernel,
                            .initrd = options.initrd,
                            .app_binary = options.app_binary,
                            .memory_size = options.memory_size,
                        }));

  // Provision keys to TVS.
  rust::Box<EnclaveClient> client = launcher->CreateClient();
  // Get TVS primary private key
  HATS_ASSIGN_OR_RETURN(std::string primary_private_key,
                        options.key_fetcher->GetPrimaryPrivateKey());
  // Send the private key to the enclave app.
  HATS_RETURN_IF_ERROR(
      client->ProvisionKeys(StringToRustSlice(primary_private_key)));

  // Load appraisal policies to enclave App.
  HATS_RETURN_IF_ERROR(client->LoadAppraisalPolicies(
      StringToRustSlice(options.appraisal_policies.SerializeAsString())));
  return std::make_unique<TvsService>(std::move(launcher),
                                      std::move(options.key_fetcher));
}

grpc::Status TvsService::VerifyReport(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) {
  rust::Box<EnclaveClient> client = launcher_->CreateClient();
  rust::Vec<std::uint8_t> session_id;
  OpaqueMessage request;
  // Read the initial message.
  if (stream->Read(&request)) {
    absl::StatusOr<CreateSessionResult> create_session_result =
        CreateSession(request, *key_fetcher_, *client);
    if (!create_session_result.status().ok()) {
      return grpc::Status(grpc::StatusCode::UNKNOWN,
                          absl::StrCat("Failed to create session.",
                                       create_session_result.status()));
    }
    session_id = create_session_result->session_id;
    OpaqueMessage response;
    response.set_binary_message(
        RustVecToString(create_session_result->binary_message));
    if (!stream->Write(response)) {
      LOG(ERROR) << "Failed to write message to stream";
      TerminateSession(
          rust::Slice<const uint8_t>(session_id.data(), session_id.size()),
          *client);
      return grpc::Status(grpc::StatusCode::UNKNOWN,
                          "Failed to write message to stream");
    }
  }

  while (stream->Read(&request)) {
    absl::StatusOr<rust::Vec<uint8_t>> result = client->DoCommand(
        rust::Slice<const uint8_t>(session_id.data(), session_id.size()),
        StringToRustSlice(request.binary_message()));
    if (!result.ok()) {
      TerminateSession(
          rust::Slice<const uint8_t>(session_id.data(), session_id.size()),
          *client);
      return grpc::Status(
          grpc::StatusCode::INVALID_ARGUMENT,
          absl::StrCat("Invalid or malformed command. ", result.status()));
    }
    OpaqueMessage response;
    response.set_binary_message(RustVecToString(*result));
    if (!stream->Write(response)) {
      TerminateSession(
          rust::Slice<const uint8_t>(session_id.data(), session_id.size()),
          *client);
      return grpc::Status(grpc::StatusCode::UNKNOWN,
                          "Failed to write message to stream");
    }
  }
  TerminateSession(
      rust::Slice<const uint8_t>(session_id.data(), session_id.size()),
      *client);
  return grpc::Status::OK;
}

}  // namespace pcit::tvs
