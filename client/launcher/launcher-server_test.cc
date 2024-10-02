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

#include "client/launcher/launcher-server.h"

#include <stdlib.h>

#include <chrono>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "client/proto/launcher.pb.h"
#include "external/oak/proto/containers/interfaces.grpc.pb.h"
#include "external/oak/proto/containers/interfaces.pb.h"
#include "gmock/gmock.h"
#include "google/protobuf/empty.pb.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "gtest/gtest.h"
#include "key_manager/key-fetcher-wrapper.h"
#include "src/google/protobuf/test_textproto.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/client/trusted-client.rs.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/untrusted_tvs/tvs-service.h"

namespace privacy_sandbox::client {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::google::protobuf::EqualsProto;
using ::grpc::ClientContext;
using ::grpc::ClientReader;
using ::oak::containers::GetImageResponse;
using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::UnorderedElementsAre;
using OakLauncher = ::oak::containers::Launcher;

absl::StatusOr<tvs::VerifyReportRequest> VerifyReportRequestFromFile(
    const std::string& file_path) {
  tvs::VerifyReportRequest verify_report_request;
  std::ifstream if_stream(file_path);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  if (!google::protobuf::TextFormat::Parse(&istream, &verify_report_request)) {
    return absl::UnknownError(
        absl::StrCat("Cannot parse proto from '", file_path, "'"));
  }
  return verify_report_request;
}

absl::StatusOr<tvs::VerifyReportRequest> GetGoodReportRequest() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  return VerifyReportRequestFromFile(runfiles->Rlocation(
      "_main/tvs/test_data/good_verify_request_report.textproto"));
}

absl::StatusOr<tvs::VerifyReportRequest> GetBadReportRequest() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  return VerifyReportRequestFromFile(runfiles->Rlocation(
      "_main/tvs/test_data/bad_verify_request_report.textproto"));
}

absl::StatusOr<tvs::AppraisalPolicies> GetTestAppraisalPolicies() {
  tvs::AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            policies {
              measurement {
                stage0_measurement {
                  amd_sev {
                    sha384: "de654ed1eb03b69567338d357f86735c64fc771676bcd5d05ca6afe86f3eb9f7549222afae6139a8d282a34d09d59f95"
                    min_tcb_version { boot_loader: 7 snp: 15 microcode: 62 }
                  }
                }
                kernel_image_sha256: "442a36913e2e299da2b516814483b6acef11b63e03f735610341a8561233f7bf"
                kernel_setup_data_sha256: "68cb426afaa29465f7c71f26d4f9ab5a82c2e1926236648bec226a8194431db9"
                init_ram_fs_sha256: "3b30793d7f3888742ad63f13ebe6a003bc9b7634992c6478a6101f9ef323b5ae"
                memory_map_sha256: "4c985428fdc6101c71cc26ddc313cd8221bcbc54471991ec39b1be026d0e1c28"
                acpi_table_sha256: "a4df9d8a64dcb9a713cec028d70d2b1599faef07ccd0d0e1816931496b4898c8"
                kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off$"
                system_image_sha256: "e3ded9e7cfd953b4ee6373fb8b412a76be102a6edd4e05aa7f8970e20bfc4bcd"
                container_binary_sha256: "bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c"
              }
              signature {
                signature: "003cfc8524266b283d4381e967680765bbd2a9ac2598eb256ba82ba98b3e23b384e72ad846c4ec3ff7b0791a53011b51d5ec1f61f61195ff083c4a97d383c13c"
                signer: "hats"
              }
            })pb",
          &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policies;
}

constexpr absl::string_view kTvsPrivateKey1 =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr absl::string_view kTvsPrivateKey2 =
    "0000000000000000000000000000000000000000000000000000000000000002";
constexpr absl::string_view kTvsPrivateKey3 =
    "0000000000000000000000000000000000000000000000000000000000000003";
constexpr absl::string_view kTvsPublicKey1 =
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2"
    "fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
constexpr absl::string_view kTvsPublicKey2 =
    "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510"
    "db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
constexpr absl::string_view kTvsPublicKey3 =
    "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c"
    "4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032";
// Authentication key registered in the test TVS server.
constexpr absl::string_view kTvsAuthenticationKey =
    "750fa48f4ddaf3201d4f1d2139878abceeb84b09dc288c17e606640eb56437a2";

absl::StatusOr<std::string> HexStringToBytes(absl::string_view hex_string) {
  std::string bytes;
  if (!absl::HexStringToBytes(hex_string, &bytes)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to convert '", hex_string, "' to bytes."));
  }
  return bytes;
}

absl::StatusOr<std::string> GenerateTmpFile(absl::string_view content) {
  char filename[] = "/tmp/hatstest-XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1)
    return absl::FailedPreconditionError(
        absl::StrCat("mkstemp() failed: ", strerror(errno)));
  std::cout << "generated temporary file at" << filename << std::endl;
  std::ofstream tmpf;
  tmpf.open(filename);
  // tmpf should have \0 attached to the end of the file although not obvious.
  // This is fine for the temporary file used for testing.
  tmpf << content;
  tmpf.close();
  if (close(fd) == -1)
    return absl::FailedPreconditionError(
        absl::StrCat("close() failed: ", strerror(errno)));
  return std::string(filename);
}

TEST(LauncherOakServer, GetContainerBundleCancelled) {
  absl::StatusOr<std::string> container_bundle_path =
      GenerateTmpFile("container_bundle");
  ASSERT_THAT(container_bundle_path, IsOk());
  LauncherOakServer launcher_oak_service(
      /*oak_image_path=*/"", *container_bundle_path, /*chunk_size=*/2);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder()
          .RegisterService(&launcher_oak_service)
          .BuildAndStart();
  ClientContext context;
  // set deadline to the past so that it'll always fail.
  std::chrono::system_clock::time_point deadline =
      std::chrono::system_clock::now() - std::chrono::milliseconds(1);
  context.set_deadline(deadline);
  google::protobuf::Empty request;
  std::unique_ptr<OakLauncher::Stub> client = OakLauncher::NewStub(
      launcher_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<ClientReader<GetImageResponse>> reader =
      client->GetContainerBundle(&context, request);
  grpc::Status status = reader->Finish();
  EXPECT_TRUE(!status.ok());
}

TEST(LauncherOakServer, GetContainerBundle) {
  absl::StatusOr<std::string> container_bundle_path =
      GenerateTmpFile("container_bundle");
  ASSERT_THAT(container_bundle_path, IsOk());
  LauncherOakServer launcher_oak_service(
      /*oak_image_path=*/"", *container_bundle_path, /*chunk_size=*/2);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder()
          .RegisterService(&launcher_oak_service)
          .BuildAndStart();
  ClientContext context;
  ::google::protobuf::Empty request;
  std::unique_ptr<OakLauncher::Stub> client = OakLauncher::NewStub(
      launcher_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<ClientReader<GetImageResponse>> reader =
      client->GetContainerBundle(&context, request);
  GetImageResponse response;
  std::string result;
  while (reader->Read(&response)) {
    result += response.image_chunk();
  }

  grpc::Status status = reader->Finish();
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(result, "container_bundle");
}

TEST(LauncherOakServer, GetOakSystemImage) {
  absl::StatusOr<std::string> oak_image_path = GenerateTmpFile("oak_image");
  ASSERT_THAT(oak_image_path, IsOk());
  LauncherOakServer launcher_oak_service(
      *oak_image_path, /*container_bundle_path=*/"", /*chunk_size=*/2);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder()
          .RegisterService(&launcher_oak_service)
          .BuildAndStart();

  ClientContext context;
  ::google::protobuf::Empty request;
  std::unique_ptr<OakLauncher::Stub> client = OakLauncher::NewStub(
      launcher_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<ClientReader<GetImageResponse>> reader =
      client->GetOakSystemImage(&context, request);
  GetImageResponse response;
  std::string result;
  while (reader->Read(&response)) {
    result += response.image_chunk();
  }

  grpc::Status status = reader->Finish();
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(result, "oak_image");
}

rust::Slice<const std::uint8_t> StringViewToRustSlice(absl::string_view str) {
  return rust::Slice<const std::uint8_t>(
      reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

std::string RustVecToString(const rust::Vec<std::uint8_t>& vec) {
  return std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
}

absl::StatusOr<std::vector<tvs::VerifyReportResponse>> RemoteVerifyReport(
    const std::unordered_map<int64_t, absl::string_view>& key_map,
    absl::string_view tvs_authentication_key,
    absl::string_view application_signing_key,
    const tvs::VerifyReportRequest& verify_report_request,
    std::shared_ptr<grpc::Channel> channel) {
  std::unordered_map<int64_t, std::string> key_hex_map;
  for (auto const& [tvs_id, pub_key] : key_map) {
    std::string tvs_public_key_bytes;
    if (!absl::HexStringToBytes(key_map.find(tvs_id)->second,
                                &tvs_public_key_bytes)) {
      return absl::InvalidArgumentError(
          "Failed to parse tvs_public_key. The key should be in hex string "
          "format");
    }
    key_hex_map[tvs_id] = std::move(tvs_public_key_bytes);
  }

  std::string tvs_authentication_key_bytes;
  if (!absl::HexStringToBytes(tvs_authentication_key,
                              &tvs_authentication_key_bytes)) {
    return absl::InvalidArgumentError(
        "Failed to parse tvs_authentication_key. The key should be in hex "
        "string format");
  }
  std::vector<tvs::VerifyReportResponse> response_vec;
  for (auto const& [tvs_id, pub_key] : key_hex_map) {
    absl::StatusOr<rust::Box<tvs::TvsClient>> tvs_client =
        tvs::NewTvsClient(StringViewToRustSlice(tvs_authentication_key_bytes),
                          StringViewToRustSlice(pub_key));
    if (!tvs_client.ok()) {
      return absl::FailedPreconditionError(absl::StrCat(
          "Failed to create trusted TVS client. ", tvs_client.status()));
    }
    absl::StatusOr<rust::Vec<uint8_t>> initial_message =
        (*tvs_client)->BuildInitialMessage();
    if (!initial_message.ok()) {
      return initial_message.status();
    }
    std::unique_ptr<LauncherService::Stub> stub =
        LauncherService::NewStub(channel);
    auto context = std::make_unique<grpc::ClientContext>();
    std::unique_ptr<
        grpc::ClientReaderWriter<ForwardingTvsMessage, tvs::OpaqueMessage>>
        stream = stub->VerifyReport(context.get());

    tvs::OpaqueMessage opaque_message;
    opaque_message.set_binary_message(RustVecToString(*initial_message));
    ForwardingTvsMessage orch_message;
    orch_message.set_tvs_id(tvs_id);
    *orch_message.mutable_opaque_message() = opaque_message;
    // orch writing to launcher (who forwards to tvs)
    if (!stream->Write(orch_message)) {
      return absl::UnknownError(
          absl::StrCat("Failed to write message to stream. ",
                       stream->Finish().error_message()));
    }
    // launcher reading from tvs
    if (!stream->Read(orch_message.mutable_opaque_message())) {
      return absl::UnknownError(
          absl::StrCat("Failed to write message to stream. ",
                       stream->Finish().error_message()));
    }

    if (absl::Status status =
            (*tvs_client)
                ->ProcessHandshakeResponse(StringViewToRustSlice(
                    orch_message.mutable_opaque_message()->binary_message()));
        !status.ok()) {
      return absl::UnknownError(
          absl::StrCat("Failed to process handshake response: ", status));
    }
    absl::StatusOr<rust::Vec<uint8_t>> encrypted_command =
        (*tvs_client)
            ->BuildVerifyReportRequest(
                StringViewToRustSlice(
                    verify_report_request.evidence().SerializeAsString()),
                StringViewToRustSlice(verify_report_request.tee_certificate()),
                std::string(application_signing_key));
    if (!encrypted_command.ok()) {
      return absl::UnknownError(absl::StrCat("Failed to process response: ",
                                             encrypted_command.status()));
    }
    orch_message.mutable_opaque_message()->set_binary_message(
        RustVecToString(*encrypted_command));
    // orch writing to launcher (forwarded to tvs)
    if (!stream->Write(orch_message)) {
      return absl::UnknownError(
          absl::StrCat("Failed to write message to stream. ",
                       stream->Finish().error_message()));
    }
    // launcher reading from tvs
    if (!stream->Read(orch_message.mutable_opaque_message())) {
      return absl::UnknownError(
          absl::StrCat("Failed to write message to stream. ",
                       stream->Finish().error_message()));
    }
    absl::StatusOr<rust::Vec<uint8_t>> secret =
        (*tvs_client)
            ->ProcessResponse(StringViewToRustSlice(
                orch_message.mutable_opaque_message()->binary_message()));
    if (!secret.ok()) {
      return absl::UnknownError(
          absl::StrCat("Failed to process response: ", secret.status()));
    }
    tvs::VerifyReportResponse response;
    if (!response.ParseFromArray(secret->data(), secret->size())) {
      return absl::UnknownError("Cannot parse result into proto");
    }
    response_vec.push_back(response);
  }
  return response_vec;
}

TEST(LauncherServer, Successful) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<tvs::AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey1);
  ASSERT_TRUE(tvs_private_key.ok());

  // Real TVS server.
  absl::StatusOr<std::unique_ptr<tvs::TvsService>> tvs_service =
      tvs::TvsService::Create({
          .primary_private_key = *std::move(tvs_private_key),
          .appraisal_policies = *std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      });
  ASSERT_TRUE(tvs_service.ok());

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(tvs_service->get()).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  // Forwarding TVS server.
  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;
  channel_map[0] = tvs_server->InProcessChannel(grpc::ChannelArguments());
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey, /*private_key_wrapping_keys=*/{},
      channel_map, /*fetch_tee_certificate=*/true);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  absl::StatusOr<tvs::VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());
  std::unordered_map<int64_t, absl::string_view> tvs_pub_keys = {
      {0, kTvsPublicKey1}};
  EXPECT_THAT(RemoteVerifyReport(
                  tvs_pub_keys, kTvsAuthenticationKey, kApplicationSigningKey,
                  *verify_report_request,
                  launcher_server->InProcessChannel(grpc::ChannelArguments())),
              IsOkAndHolds(UnorderedElementsAre(EqualsProto(R"pb(
                secrets {
                  key_id: 64
                  public_key: "1-public-key"
                  private_key: "1-secret"
                })pb"))));
}

TEST(LauncherServer, SplitSuccessful) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<tvs::AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key1 =
      HexStringToBytes(kTvsPrivateKey1);
  ASSERT_TRUE(tvs_private_key1.ok());
  absl::StatusOr<std::string> tvs_private_key2 =
      HexStringToBytes(kTvsPrivateKey2);
  ASSERT_TRUE(tvs_private_key2.ok());
  absl::StatusOr<std::string> tvs_private_key3 =
      HexStringToBytes(kTvsPrivateKey3);
  ASSERT_TRUE(tvs_private_key3.ok());

  // TVS Service 1.
  absl::StatusOr<std::unique_ptr<tvs::TvsService>> tvs_service1 =
      tvs::TvsService::Create({
          .primary_private_key = *std::move(tvs_private_key1),
          .appraisal_policies = *appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      });
  ASSERT_TRUE(tvs_service1.ok());

  // TVS Service 2
  absl::StatusOr<std::unique_ptr<tvs::TvsService>> tvs_service2 =
      tvs::TvsService::Create({
          .primary_private_key = *std::move(tvs_private_key2),
          .appraisal_policies = *appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      });
  ASSERT_TRUE(tvs_service2.ok());

  // TVS Service 3
  absl::StatusOr<std::unique_ptr<tvs::TvsService>> tvs_service3 =
      tvs::TvsService::Create({
          .primary_private_key = *std::move(tvs_private_key3),
          .appraisal_policies = *appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      });
  ASSERT_TRUE(tvs_service3.ok());

  std::unique_ptr<grpc::Server> tvs_server1 =
      grpc::ServerBuilder()
          .RegisterService(tvs_service1->get())
          .BuildAndStart();

  std::unique_ptr<grpc::Server> tvs_server2 =
      grpc::ServerBuilder()
          .RegisterService(tvs_service2->get())
          .BuildAndStart();

  std::unique_ptr<grpc::Server> tvs_server3 =
      grpc::ServerBuilder()
          .RegisterService(tvs_service3->get())
          .BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  // Forwarding TVS server.
  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;
  channel_map[0] = tvs_server1->InProcessChannel(grpc::ChannelArguments());
  channel_map[1] = tvs_server2->InProcessChannel(grpc::ChannelArguments());
  channel_map[2] = tvs_server3->InProcessChannel(grpc::ChannelArguments());
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey,
      /*private_key_wrapping_keys=*/{}, channel_map,
      /*fetch_tee_certificate=*/true);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  absl::StatusOr<tvs::VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());
  std::unordered_map<int64_t, absl::string_view> tvs_pub_keys = {
      {0, kTvsPublicKey1},
      {1, kTvsPublicKey2},
      {2, kTvsPublicKey3},
  };
  // Currently we don't have a good way to change the secret because the
  // EchoKeyFetcher returns the same userID from every TVS
  EXPECT_THAT(RemoteVerifyReport(
                  tvs_pub_keys, kTvsAuthenticationKey, kApplicationSigningKey,
                  *verify_report_request,
                  launcher_server->InProcessChannel(grpc::ChannelArguments())),
              IsOkAndHolds(UnorderedElementsAre(EqualsProto(R"pb(
                                                  secrets {
                                                    key_id: 64
                                                    public_key: "1-public-key"
                                                    private_key: "1-secret"
                                                  })pb"),
                                                EqualsProto(R"pb(
                                                  secrets {
                                                    key_id: 64
                                                    public_key: "1-public-key"
                                                    private_key: "1-secret"
                                                  })pb"),
                                                EqualsProto(R"pb(
                                                  secrets {
                                                    key_id: 64
                                                    public_key: "1-public-key"
                                                    private_key: "1-secret"
                                                  })pb"))));
}

TEST(LauncherServer, BadReportError) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<tvs::AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());

  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey1);
  ASSERT_TRUE(tvs_private_key.ok());
  // Real TVS server.
  absl::StatusOr<std::unique_ptr<tvs::TvsService>> tvs_service =
      tvs::TvsService::Create({
          .primary_private_key = *std::move(tvs_private_key),
          .appraisal_policies = *std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      });
  ASSERT_TRUE(tvs_service.ok());

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(tvs_service->get()).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  // Forwarding TVS server.
  std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>> channel_map;
  channel_map[0] = tvs_server->InProcessChannel(grpc::ChannelArguments());
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey, PrivateKeyWrappingKeys{},
      channel_map, /*fetch_tee_certificate=*/true);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();

  absl::StatusOr<tvs::VerifyReportRequest> verify_report_request =
      GetBadReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  constexpr absl::string_view kApplicationSigningKey =
      "df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759";
  std::unordered_map<int64_t, absl::string_view> tvs_pub_keys = {
      {0, kTvsPublicKey1}};
  absl::StatusOr<std::vector<tvs::VerifyReportResponse>> report_vec =
      RemoteVerifyReport(
          tvs_pub_keys, kTvsAuthenticationKey, kApplicationSigningKey,
          *verify_report_request,
          launcher_server->InProcessChannel(grpc::ChannelArguments()));
  EXPECT_THAT(report_vec,
              StatusIs(absl::StatusCode::kUnknown,
                       AllOf(HasSubstr("Failed to verify report"),
                             HasSubstr("No matching appraisal policy found"))));
}

}  // namespace

}  // namespace privacy_sandbox::client
