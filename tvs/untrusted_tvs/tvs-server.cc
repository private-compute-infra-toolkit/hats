#include "tvs/untrusted_tvs/tvs-server.h"

#include <cstdlib>
#include <iostream>
#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "grpc/grpc.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/server_context.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/trusted_tvs/src/lib.rs.h"

namespace privacy_sandbox::tvs {

namespace {

rust::Slice<const std::uint8_t> StringToRustSlice(const std::string& str) {
  return rust::Slice<const std::uint8_t>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size());
}
std::string RustVecToString(const rust::Vec<std::uint8_t>& vec) {
  return std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
}

}  // namespace

absl::StatusOr<rust::Box<TrustedTvs>> CreateTrustedTvsService(
    const std::string& tvs_private_key) {
  // try/catch is to handle errors from rust code.
  // Errors returned by rust functions are converted to C++ exception.
  try {
    return new_trusted_tvs_service(tvs_private_key);
  } catch (std::exception& e) {
    return absl::FailedPreconditionError(
        absl::StrCat("Cannot create trusted TVS server. ", e.what()));
  }
}

TvsServer::TvsServer(const std::string& tvs_private_key)
    : tvs_private_key_(tvs_private_key) {}

grpc::Status TvsServer::VerifyReport(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) {
  absl::StatusOr<rust::Box<TrustedTvs>> trusted_tvs =
      CreateTrustedTvsService(tvs_private_key_);
  if (!trusted_tvs.ok()) {
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        trusted_tvs.status().ToString());
  }
  // try/catch is to handle errors from rust code.
  // Errors returned by rust functions are converted to C++ exception.
  try {
    OpaqueMessage request;
    while (stream->Read(&request)) {
      rust::Vec<std::uint8_t> result =
          (*trusted_tvs)
              ->verify_report(StringToRustSlice(request.binary_message()));
      OpaqueMessage response;
      response.set_binary_message(RustVecToString(result));
      if (!stream->Write(response)) {
        LOG(ERROR) << "Failed to write message to stream";
        return grpc::Status(grpc::StatusCode::UNKNOWN,
                            "Failed to write message to stream");
      }
    }
  } catch (std::exception& e) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "Invalid or malformed command.");
  }
  return grpc::Status::OK;
}

void CreateAndStartTvsServer(const TvsServerOptions& options) {
  std::string server_address = absl::StrCat("0.0.0.0:", options.port);
  TvsServer tvs_server(options.tvs_private_key);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder()
          .AddListeningPort(server_address, grpc::InsecureServerCredentials())
          .RegisterService(&tvs_server)
          .BuildAndStart();
  LOG(INFO) << "Server listening on " << server_address;
  server->Wait();
}

}  // namespace privacy_sandbox::tvs
