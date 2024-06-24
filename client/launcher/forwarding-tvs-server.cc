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
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/interceptor.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

ForwardingTvsServer::ForwardingTvsServer(std::shared_ptr<grpc::Channel> channel)
    : stub_(TeeVerificationService::NewStub(channel)) {}

grpc::Status ForwardingTvsServer::VerifyReport(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) {
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
