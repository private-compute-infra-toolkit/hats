#ifndef HATS_TVS_UNTRUSTED_TVS_SERVER_
#define HATS_TVS_UNTRUSTED_TVS_SERVER_

#include <string>

#include "external/oak/proto/attestation/reference_value.pb.h"
#include "grpcpp/server_context.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
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
  // Pass appraisal_policy by value as we expect the caller to use std::move().
  explicit TvsServer(const std::string& tvs_private_key,
                     oak::attestation::v1::ReferenceValues appraisal_policy);
  TvsServer() = delete;
  grpc::Status VerifyReport(
      grpc::ServerContext* context,
      grpc::ServerReaderWriter<OpaqueMessage, OpaqueMessage>* stream) override;

 private:
  const std::string tvs_private_key_;
  const oak::attestation::v1::ReferenceValues appraisal_policy_;
};

struct TvsServerOptions {
  int port;
  // TODO(alwabel): implement a better key provisioning.
  std::string tvs_private_key;
  oak::attestation::v1::ReferenceValues appraisal_policy;
};

// Starts a server and blocks forever.
// Pass by value as we expect the caller to use std::move() or use temporaries.
void CreateAndStartTvsServer(TvsServerOptions options);

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_UNTRUSTED_TVS_SERVER_
