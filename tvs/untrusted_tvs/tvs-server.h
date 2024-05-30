#ifndef HATS_TVS_UNTRUSTED_TVS_SERVER_
#define HATS_TVS_UNTRUSTED_TVS_SERVER_
#include <string>

#include "grpcpp/server.h"
#include "grpcpp/server_context.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"

namespace privacy_sandbox::tvs {

// An implementation of TeeVerificationService.
// The service exports one bidirectional streaming rpc, namely VerifyReport.
// The server acts as a pipe between clients and the trusted tee verification
// service. The server is agnostic toe the messages. It receives bytes from gRPC
// clients, passes them to the trusted TVS, and pass back bytes received from
// the trusted TVS to client. The trusted TVS expect the following flow:
// 1. Client initiate noise handshake.
// 2. Server responds to the handshake with an ephemeral public key.
// 3. Client sends attestation report.
// 4. Server verifies the report and mints a JWT token.
class TvsServer final : public TeeVerificationService::Service {
 public:
  explicit TvsServer(const std::string& tvs_private_key);
  TvsServer() = delete;
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) override;

 private:
  const std::string tvs_private_key_;
};

struct TvsServerOptions {
  int port;
  // TODO(alwabel): implement a better key provisioning.
  std::string tvs_private_key;
};

// Starts a server and blocks forever.
void CreateAndStartTvsServer(const TvsServerOptions& options);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_UNTRUSTED_TVS_SERVER_
