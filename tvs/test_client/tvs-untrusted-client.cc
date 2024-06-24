#include "tvs/test_client/tvs-untrusted-client.h"

#include <cstdint>
#include <exception>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "grpcpp/client_context.h"
#include "grpcpp/support/interceptor.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/client/trusted-client.rs.h"
#include "tvs/proto/tvs.grpc.pb.h"

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
  // try/catch is to handle errors from rust code.
  // Errors returned by rust functions are converted to C++ exception.
  try {
    const rust::Vec<std::uint8_t> initial_message =
        tvs_client.build_initial_message();
    OpaqueMessage opaque_message;
    opaque_message.set_binary_message(RustVecToString(initial_message));
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
    tvs_client.process_handshake_response(
        StringToRustSlice(opaque_message.binary_message()));
  } catch (std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to finish noise handshake.", e.what()));
  }
  return absl::OkStatus();
}

}  // namespace

TvsUntrustedClient::TvsUntrustedClient(
    std::unique_ptr<TeeVerificationService::Stub> stub,
    std::unique_ptr<grpc::ClientContext> context,
    std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
        stream,
    rust::Box<TvsClient> tvs_client)
    : stub_(std::move(stub)),
      context_(std::move(context)),
      stream_(std::move(stream)),
      tvs_client_(std::move(tvs_client)) {}

absl::StatusOr<std::unique_ptr<TvsUntrustedClient>>
TvsUntrustedClient::CreateClient(const Options& options) {
  // try/catch is to handle errors from rust code.
  // Errors returned by rust functions are converted to C++ exception.
  try {
    rust::Box<TvsClient> tvs_client = new_tvs_client(options.tvs_public_key);
    // Perform handshake.
    std::unique_ptr<TeeVerificationService::Stub> stub =
        TeeVerificationService::NewStub(options.channel);
    auto context = std::make_unique<grpc::ClientContext>();
    std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
        stream = stub->VerifyReport(context.get());

    if (absl::Status status = PerformNoiseHandshake(*stream, *tvs_client);
        !status.ok()) {
      return status;
    }
    return absl::WrapUnique(
        new TvsUntrustedClient(std::move(stub), std::move(context),
                               std::move(stream), std::move(tvs_client)));
  } catch (std::exception& e) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to create trusted TVS client.", e.what()));
  }
}

absl::StatusOr<std::string> TvsUntrustedClient::VerifyReportAndGetToken(
    const std::string& application_signing_key,
    const VerifyReportRequest& verify_report_request) {
  // try/catch is to handle errors from rust code.
  // Errors returned by rust functions are converted to C++ exception.
  try {
    const rust::Vec<std::uint8_t> encrypted_command =
        tvs_client_->build_verify_report_request(
            StringToRustSlice(
                verify_report_request.evidence().SerializeAsString()),
            StringToRustSlice(verify_report_request.tee_certificate()),
            application_signing_key);
    OpaqueMessage opaque_message;
    opaque_message.set_binary_message(RustVecToString(encrypted_command));

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
    std::string token(tvs_client_->process_response(
        StringToRustSlice(opaque_message.binary_message())));
    return token;
  } catch (std::exception& e) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to create trusted TVS client.", e.what()));
  }
  return absl::OkStatus();
}

}  // namespace privacy_sandbox::tvs
