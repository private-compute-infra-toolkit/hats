#ifndef HATS_TVS_TEST_CLIENT_TVS_UNTRUSTED_CLIENT_H_
#define HATS_TVS_TEST_CLIENT_TVS_UNTRUSTED_CLIENT_H_

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "grpcpp/channel.h"
#include "grpcpp/client_context.h"
#include "tvs/proto/tvs.grpc.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-trusted-client.rs.h"

namespace privacy_sandbox::tvs {

// Communicate with a TVS server and fetches a JWT token. The class sends an
// attestation report and gets a JWT token from a TVS server over a streaming
// gRPC channel. The class performs noise handshake, and necessary proto
// encoding/decoding.
class TvsUntrustedClient final {
  struct Options {
    std::string tvs_public_key;
    std::shared_ptr<grpc::Channel> channel = nullptr;
  };

 public:
  TvsUntrustedClient() = delete;
  TvsUntrustedClient(const TvsUntrustedClient& arg) = delete;
  TvsUntrustedClient(TvsUntrustedClient&& arg) = delete;
  TvsUntrustedClient& operator=(const TvsUntrustedClient& rhs) = delete;
  TvsUntrustedClient& operator=(TvsUntrustedClient& rhs) = delete;

  ~TvsUntrustedClient();

  static absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> CreateClient(
      const Options& options);

  // Get JWT token from TVS server.
  absl::StatusOr<std::string> VerifyReportAndGetToken(
      const std::string& report);

 private:
  TvsUntrustedClient(
      std::unique_ptr<TeeVerificationService::Stub> stub,
      std::unique_ptr<grpc::ClientContext> context,
      std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
          stream,
      rust::Box<test_client::TvsClient> tvs_client);
  std::unique_ptr<TeeVerificationService::Stub> stub_;
  std::unique_ptr<grpc::ClientContext> context_;
  std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
      stream_;
  rust::Box<test_client::TvsClient> tvs_client_;
};

}  // namespace privacy_sandbox::tvs

#endif  // HATS_TVS_TEST_CLIENT_TVS_UNTRUSTED_CLIENT_H_
