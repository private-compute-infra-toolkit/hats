#ifndef HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_
#define HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_

#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

// Grpc server that pipes messages between the client and the server.
// The server is used to proxy communication between the orchestrator
// and Tvs.
class ForwardingTvsServer final : public TeeVerificationService::Service {
 public:
  ForwardingTvsServer(std::shared_ptr<grpc::Channel> channel);
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) override;

 private:
  std::unique_ptr<TeeVerificationService::Stub> stub_;
};

// Starts a server and blocks forever.
void CreateAndStartForwardingTvsServer(int port,
                                       std::shared_ptr<grpc::Channel> channel);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_CLIENT_LAUNCHER_FORWARDING_TVS_SERVER_
