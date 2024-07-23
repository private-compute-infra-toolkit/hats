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

#include "client/launcher/forwarding-tvs-server.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "client/launcher/certificates.rs.h"
#include "client/proto/launcher.grpc.pb.h"
#include "grpcpp/channel.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "rust/cxx.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

namespace {
using privacy_sandbox::launcher::FetchTeeCertificateRequest;
using privacy_sandbox::launcher::FetchTeeCertificateResponse;
std::string RustVecToString(const rust::Vec<std::uint8_t> &vec) {
  return std::string(reinterpret_cast<const char *>(vec.data()), vec.size());
}
}  // namespace

ForwardingTvsServer::ForwardingTvsServer(std::shared_ptr<grpc::Channel> channel)
    : stub_(TeeVerificationService::NewStub(channel)) {}

grpc::Status ForwardingTvsServer::FetchTeeCertificate(
    grpc::ServerContext *context, const FetchTeeCertificateRequest *request,
    FetchTeeCertificateResponse *reply) {
  try {
    reply->set_signature(
        RustVecToString(privacy_sandbox::launcher::get_vcek()));
    return grpc::Status::OK;
  } catch (rust::Error error) {
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, error.what());
  }
}

grpc::Status ForwardingTvsServer::VerifyReport(
    grpc::ServerContext *context,
    grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage> *stream) {
  auto remote_context = std::make_unique<grpc::ClientContext>();
  std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
      remote_stream = stub_->VerifyReport(remote_context.get());
  OpaqueMessage opaque_message;
  while (stream->Read((&opaque_message))) {
    if (!remote_stream->Write(opaque_message)) {
      return grpc::Status(
          grpc::StatusCode::UNKNOWN,
          absl::StrCat("Failed to write to stream. ",
                       remote_stream->Finish().error_message()));
    }
    if (!remote_stream->Read(&opaque_message)) {
      return grpc::Status(
          grpc::StatusCode::UNKNOWN,
          absl::StrCat("Failed to read from stream. ",
                       remote_stream->Finish().error_message()));
    }
    // Send the message back to the client.
    if (!stream->Write(opaque_message)) {
      return grpc::Status(grpc::StatusCode::UNKNOWN,
                          "Failed to write message to stream. ");
    }
  }
  return grpc::Status::OK;
}

void CreateAndStartForwardingTvsServer(int port,
                                       std::shared_ptr<grpc::Channel> channel) {
  const std::string server_address = absl::StrCat("0.0.0.0:", port);
  ForwardingTvsServer forwarding_tvs_server(channel);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder()
          .AddListeningPort(server_address, grpc::InsecureServerCredentials())
          .RegisterService(&forwarding_tvs_server)
          .BuildAndStart();
  LOG(INFO) << "Server listening on " << server_address;
  server->Wait();
}

}  // namespace privacy_sandbox::tvs
