#include "tvs/untrusted_tvs/tvs-server.h"

#include <string>

#include "gmock/gmock.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "gtest/gtest.h"
#include "tvs/test_client/tvs-untrusted-client.h"

namespace privacy_sandbox::tvs {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

constexpr absl::string_view kPrivateKey =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr absl::string_view kPublicKey =
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2"
    "fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

TEST(TvsServer, Successful) {
  std::string key = std::string(kPrivateKey);
  TvsServer tvs_server(key);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kPublicKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });
  ASSERT_TRUE(tvs_client.ok());

  // Ensure that the client can send multiple requests to verify reports within
  // the same session without the need to redo the handshake.
  for (int i = 0; i < 10; ++i) {
    absl::StatusOr<std::string> token =
        (*tvs_client)->VerifyReportAndGetToken("verify");
    // We don't have status matcher; otherwise we would use the following:
    // EXPECT_THAT(.., IsOkAndHolds(...));
    ASSERT_TRUE(token.ok());
    // We match against the header only.
    EXPECT_THAT(*token, HasSubstr("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"));
  }
}

TEST(TvsServer, MalformedMessage) {
  std::string key = std::string(kPrivateKey);
  TvsServer tvs_server(key);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();
  std::unique_ptr<TeeVerificationService::Stub> stub =
      TeeVerificationService::NewStub(
          server->InProcessChannel(grpc::ChannelArguments()));
  grpc::ClientContext client_context;
  std::unique_ptr<grpc::ClientReaderWriter<OpaqueMessage, OpaqueMessage>>
      stream = stub->VerifyReport(&client_context);
  OpaqueMessage request;
  request.set_binary_message("garbage");
  ASSERT_TRUE(stream->Write(request));
  OpaqueMessage response;
  ASSERT_FALSE(stream->Read(&response));
  EXPECT_THAT(stream->Finish().error_message(),
              HasSubstr("Invalid or malformed command."));
}

TEST(TvsServer, ErrorCreatingTrustedTvsServer) {
  TvsServer tvs_server("0000");
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kPublicKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });

  ASSERT_FALSE(tvs_client.ok());
  EXPECT_THAT(
      tvs_client.status().message(),
      AllOf(HasSubstr("FAILED_PRECONDITION: Cannot create trusted TVS server"),
            HasSubstr(
                "Invalid private key length. Key should be 32 bytes long.")));
}

}  // namespace
}  // namespace privacy_sandbox::tvs
