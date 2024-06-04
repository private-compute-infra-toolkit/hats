#include "tvs/untrusted_tvs/tvs-server.h"

#include <fstream>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/client_context.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "gtest/gtest.h"
#include "proto/attestation/reference_value.pb.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

namespace privacy_sandbox::tvs {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::AllOf;
using ::testing::HasSubstr;

constexpr absl::string_view kPrivateKey =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr absl::string_view kPublicKey =
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2"
    "fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

absl::StatusOr<VerifyReportRequest> VerifyReportRequestFromFile(
    const std::string& file_path) {
  VerifyReportRequest verify_report_request;
  std::ifstream if_stream(file_path);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  if (!google::protobuf::TextFormat::Parse(&istream, &verify_report_request)) {
    return absl::UnknownError(
        absl::StrCat("Cannot parse proto from '", file_path, "'"));
  }
  return verify_report_request;
}

absl::StatusOr<VerifyReportRequest> GetGoodReportRequest() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  return VerifyReportRequestFromFile(runfiles->Rlocation(
      "_main/tvs/test_data/good_verify_request_report.prototext"));
}

absl::StatusOr<VerifyReportRequest> GetBadReportRequest() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  return VerifyReportRequestFromFile(runfiles->Rlocation(
      "_main/tvs/test_data/bad_verify_request_report.prototext"));
}

absl::StatusOr<oak::attestation::v1::ReferenceValues> GetTestAppraisalPolicy() {
  oak::attestation::v1::ReferenceValues appraisal_policy;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            oak_containers {
              root_layer {
                amd_sev {
                  stage0 { skip {} }
                  min_tcb_version {}
                }
              }
              kernel_layer {
                kernel { skip {} }
                init_ram_fs { skip {} }
                memory_map { skip {} }
                acpi { skip {} }
                kernel_cmd_line_text {
                  string_literals {
                    value: "console=ttyS0 panic=-1 earlycon=uart,io,0x3F8 brd.rd_nr=1 brd.rd_size=3072000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off net.ifnames=0 quiet"
                  }
                }
              }
              system_layer { system_image { skip {} } }
              container_layer {
                binary { skip {} }
                configuration { skip {} }
              }
            })pb",
          &appraisal_policy)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policy;
}

TEST(TvsServer, Successful) {
  std::string key = std::string(kPrivateKey);
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(appraisal_policy.ok());

  TvsServer tvs_server(key, *std::move(appraisal_policy));
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kPublicKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  // Ensure that the client can send multiple requests to verify reports within
  // the same session without the need to redo the handshake.
  for (int i = 0; i < 10; ++i) {
    // We match against the header only.
    EXPECT_THAT(
        (*tvs_client)->VerifyReportAndGetToken(*verify_report_request),
        IsOkAndHolds(HasSubstr("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9")));
  }
}

TEST(TvsServer, BadReportError) {
  std::string key = std::string(kPrivateKey);
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(appraisal_policy.ok());
  TvsServer tvs_server(key, *std::move(appraisal_policy));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kPublicKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetBadReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  EXPECT_THAT((*tvs_client)->VerifyReportAndGetToken(*verify_report_request),
              StatusIs(absl::StatusCode::kUnknown,
                       AllOf(HasSubstr("Failed to verify report"),
                             HasSubstr("chip id differs"))));
}

TEST(TvsServer, MalformedMessageError) {
  std::string key = std::string(kPrivateKey);
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(appraisal_policy.ok());

  TvsServer tvs_server(key, *std::move(appraisal_policy));
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

TEST(TvsServer, CreatingTrustedTvsServerError) {
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(appraisal_policy.ok());
  TvsServer tvs_server("0000", *std::move(appraisal_policy));
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  EXPECT_THAT(
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kPublicKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }),
      StatusIs(
          absl::StatusCode::kUnknown,
          AllOf(HasSubstr(
                    "FAILED_PRECONDITION: Cannot create trusted TVS server"),
                HasSubstr("Invalid private key length. Key should be 32 bytes "
                          "long."))));
}

}  // namespace
}  // namespace privacy_sandbox::tvs
