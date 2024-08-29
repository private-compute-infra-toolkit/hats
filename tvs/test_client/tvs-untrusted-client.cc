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

#include "tvs/test_client/tvs-untrusted-client.h"

#include <cstdint>
#include <exception>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "client/proto/launcher.grpc.pb.h"
#include "grpcpp/client_context.h"
#include "grpcpp/support/interceptor.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/client/trusted-client.rs.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

namespace {

std::string RustVecToString(const rust::Vec<std::uint8_t>& vec) {
  return std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
}

rust::Slice<const std::uint8_t> StringToRustSlice(const std::string& str) {
  return rust::Slice<const std::uint8_t>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

absl::Status PerformNoiseHandshake(
    grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>& stream,
    TvsClient& tvs_client) {
  const VecU8Result initial_message = tvs_client.BuildInitialMessage();
  if (!initial_message.error.empty()) {
    return absl::UnknownError(absl::StrCat("Failed to build initial message: ",
                                           std::string(initial_message.error)));
  }

  OpaqueMessage opaque_message;
  opaque_message.set_binary_message(RustVecToString(initial_message.value));
  if (!stream.Write(opaque_message)) {
    return absl::UnknownError(
        absl::StrCat("Failed to write message to stream. ",
                     stream.Finish().error_message()));
  }
  if (!stream.Read(&opaque_message)) {
    return absl::UnknownError(
        absl::StrCat("Failed to write message to stream. ",
                     stream.Finish().error_message()));
  }

  if (rust::String status = tvs_client.ProcessHandshakeResponse(
          StringToRustSlice(opaque_message.binary_message()));
      !status.empty()) {
    return absl::UnknownError(absl::StrCat(
        "Failed to process handshake response: ", std::string(status)));
  }
  return absl::OkStatus();
}

}  // namespace

TvsUntrustedClient::TvsUntrustedClient(
    std::unique_ptr<privacy_sandbox::client::LauncherService::Stub>
        launcher_stub,
    std::unique_ptr<TeeVerificationService::Stub> stub,
    std::unique_ptr<grpc::ClientContext> context,
    std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
        stream,
    rust::Box<TvsClient> tvs_client)
    : launcher_stub_(std::move(launcher_stub)),
      stub_(std::move(stub)),
      context_(std::move(context)),
      stream_(std::move(stream)),
      tvs_client_(std::move(tvs_client)) {}

absl::StatusOr<std::unique_ptr<TvsUntrustedClient>>
TvsUntrustedClient::CreateClient(const Options& options) {
  std::string tvs_public_key;
  if (!absl::HexStringToBytes(options.tvs_public_key, &tvs_public_key)) {
    return absl::InvalidArgumentError(
        "Failed to parse tvs_public_key. The key should be in hex string "
        "format");
  }

  std::string tvs_authentication_key;
  if (!absl::HexStringToBytes(options.tvs_authentication_key,
                              &tvs_authentication_key)) {
    return absl::InvalidArgumentError(
        "Failed to parse tvs_authentication_key. The key should be in hex "
        "string format");
  }

  TvsClientCreationResult tvs_client_result =
      NewTvsClient(StringToRustSlice(tvs_authentication_key),
                   StringToRustSlice(tvs_public_key));
  if (!tvs_client_result.error.empty()) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to create trusted TVS client. ",
                     std::string(tvs_client_result.error)));
  }

  auto tvs_client = rust::Box<TvsClient>::from_raw(tvs_client_result.value);

  // Perform handshake.
  std::unique_ptr<TeeVerificationService::Stub> stub = nullptr;
  std::unique_ptr<privacy_sandbox::client::LauncherService::Stub>
      launcher_stub = nullptr;

  if (options.use_launcher_forwarding) {
    launcher_stub =
        privacy_sandbox::client::LauncherService::LauncherService::NewStub(
            options.channel);
  } else {
    stub = TeeVerificationService::NewStub(options.channel);
  }
  auto context = std::make_unique<grpc::ClientContext>();
  std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
      stream;
  if (stub != nullptr) {
    stream = stub->VerifyReport(context.get());
  } else {
    stream = launcher_stub->VerifyReport(context.get());
  }
  if (absl::Status status = PerformNoiseHandshake(*stream, *tvs_client);
      !status.ok()) {
    return status;
  }
  return absl::WrapUnique(new TvsUntrustedClient(
      std::move(launcher_stub), std::move(stub), std::move(context),
      std::move(stream), std::move(tvs_client)));
}

absl::StatusOr<VerifyReportResponse>
TvsUntrustedClient::VerifyReportAndGetSecrets(
    const std::string& application_signing_key,
    const VerifyReportRequest& verify_report_request) {
  const VecU8Result encrypted_command = tvs_client_->BuildVerifyReportRequest(
      StringToRustSlice(verify_report_request.evidence().SerializeAsString()),
      StringToRustSlice(verify_report_request.tee_certificate()),
      application_signing_key);
  if (!encrypted_command.error.empty()) {
    return absl::UnknownError(absl::StrCat(
        "Failed to process response: ", std::string(encrypted_command.error)));
  }
  OpaqueMessage opaque_message;
  opaque_message.set_binary_message(RustVecToString(encrypted_command.value));

  if (!stream_->Write(opaque_message)) {
    return absl::UnknownError(
        absl::StrCat("Failed to write message to stream. ",
                     stream_->Finish().error_message()));
  }

  if (!stream_->Read(&opaque_message)) {
    return absl::UnknownError(
        absl::StrCat("Failed to write message to stream. ",
                     stream_->Finish().error_message()));
  }

  const VecU8Result secret = tvs_client_->ProcessResponse(
      StringToRustSlice(opaque_message.binary_message()));
  if (!secret.error.empty()) {
    return absl::UnknownError(absl::StrCat("Failed to process response: ",
                                           std::string(secret.error)));
  }
  VerifyReportResponse response;
  if (!response.ParseFromArray(secret.value.data(), secret.value.size())) {
    return absl::UnknownError("Cannot parse result into proto");
  }
  return response;
}

}  // namespace privacy_sandbox::tvs
