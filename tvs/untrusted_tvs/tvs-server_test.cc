#include "tvs/untrusted_tvs/tvs-server.h"

#include <filesystem>
#include <fstream>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "external/oak/proto/attestation/reference_value.pb.h"
#include "gmock/gmock.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/proto/tvs_messages.pb.h"
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

struct BinaryFile {
  std::unique_ptr<char[]> buffer;
  size_t size;
};

absl::StatusOr<BinaryFile> ReadBinaryFile(const std::string& file_path) {
  size_t size = std::filesystem::file_size(file_path);
  auto buffer = std::make_unique<char[]>(size);
  std::ifstream file(file_path, std::ifstream::binary);
  if (!file) {
    return absl::UnknownError(absl::StrCat("Failed to open '", file_path, "'"));
  }
  file.read(buffer.get(), size);
  if (!file) {
    return absl::UnknownError(absl::StrCat("Failed to read '", size,
                                           "' bytes from '", file_path, "'"));
  }
  file.close();
  return BinaryFile{
      .buffer = std::move(buffer),
      .size = size,
  };
}

absl::StatusOr<VerifyReportRequest> GetGoodReportRequest() {
  // TODO(alwabel): Investigate if its acceptable to use `ParseTextProtoOrDie()`
  // from
  // https://github.com/google-ai-edge/mediapipe/blob/2da0c56a5df3463af869dc365339225f0553d43b/mediapipe/framework/port/parse_text_proto.h#L31.
  VerifyReportRequest verify_report_request;
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  absl::StatusOr<BinaryFile> vcek_buffer = ReadBinaryFile(
      runfiles->Rlocation("_main/tvs/test_data/oc_vcek_milan.der"));
  if (!vcek_buffer.ok()) {
    return vcek_buffer.status();
  }
  verify_report_request.set_tee_certificate(
      std::string(vcek_buffer->buffer.get(), vcek_buffer->size));
  const std::string evidence_file_path =
      runfiles->Rlocation("_main/tvs/test_data/oc_evidence.binarypb");
  absl::StatusOr<BinaryFile> evidence_buffer =
      ReadBinaryFile(evidence_file_path);
  if (!evidence_buffer.ok()) {
    return evidence_buffer.status();
  }
  if (!verify_report_request.mutable_evidence()->ParseFromArray(
          evidence_buffer->buffer.get(), evidence_buffer->size)) {
    return absl::UnknownError(absl::StrCat("Failed to decode proto in file '",
                                           evidence_file_path, "'"));
  }
  return verify_report_request;
}

absl::StatusOr<VerifyReportRequest> GetBadReportRequest() {
  VerifyReportRequest verify_report_request;
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  absl::StatusOr<BinaryFile> vcek_buffer = ReadBinaryFile(
      runfiles->Rlocation("_main/tvs/test_data/oc_vcek_milan.der"));
  if (!vcek_buffer.ok()) {
    return vcek_buffer.status();
  }
  verify_report_request.set_tee_certificate(
      std::string(vcek_buffer->buffer.get(), vcek_buffer->size));
  const std::string evidence_file_path =
      runfiles->Rlocation("_main/tvs/test_data/bad_evidence.binarypb");
  absl::StatusOr<BinaryFile> evidence_buffer =
      ReadBinaryFile(evidence_file_path);
  if (!evidence_buffer.ok()) {
    return evidence_buffer.status();
  }
  if (!verify_report_request.mutable_evidence()->ParseFromArray(
          evidence_buffer->buffer.get(), evidence_buffer->size)) {
    return absl::UnknownError(absl::StrCat("Failed to decode proto in file '",
                                           evidence_file_path, "'"));
  }
  return verify_report_request;
}

// TODO(alwabel): make reading test data consistent. Either read all from binary
// proto files, or parse from inline texts.
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
    absl::StatusOr<std::string> token =
        (*tvs_client)->VerifyReportAndGetToken(*verify_report_request);
    // We don't have status matcher; otherwise we would use the following:
    // EXPECT_THAT(.., IsOkAndHolds(...));
    ASSERT_TRUE(token.ok());
    // We match against the header only.
    EXPECT_THAT(*token, HasSubstr("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"));
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
  absl::StatusOr<std::string> token =
      (*tvs_client)->VerifyReportAndGetToken(*verify_report_request);
  ASSERT_FALSE(token.ok());
  EXPECT_THAT(token.status().message(),
              AllOf(HasSubstr("Failed to verify report"),
                    HasSubstr("chip id differs")));
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
