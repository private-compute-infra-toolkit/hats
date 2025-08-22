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
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "client/proto/launcher.pb.h"
#include "crypto/test-ec-key.h"
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
#include "key_manager/test-key-fetcher.h"
#include "proto/attestation/evidence.pb.h"
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/client/trusted-client.rs.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/standalone_server/tvs-service.h"

#ifdef DYNAMIC_ATTESTATION
#include "tvs/test_utils_cc/policy_generator.h"
#endif

namespace pcit::client {
namespace {

using ::google::protobuf::EqualsProto;
using ::grpc::ClientContext;
using ::grpc::ClientReader;
using ::oak::containers::GetImageResponse;
using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::UnorderedElementsAre;
using OakLauncher = ::oak::containers::Launcher;

absl::StatusOr<oak::attestation::v1::Evidence> EvidenceFromFile(
    const std::string& file_path) {
  oak::attestation::v1::Evidence evidence;
  std::ifstream if_stream(file_path);
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  if (!google::protobuf::TextFormat::Parse(&istream, &evidence)) {
    return absl::UnknownError(
        absl::StrCat("Cannot parse proto from '", file_path, "'"));
  }
  return evidence;
}

absl::StatusOr<std::string> ReadBinaryFile(const std::string& path) {
  std::ifstream if_stream(path);
  if (!if_stream.is_open()) {
    return absl::UnknownError(absl::StrCat("Cannot open file at '", path, "'"));
  }
  if_stream.seekg(0, std::ios::end);
  std::streampos file_size = if_stream.tellg();
  if_stream.seekg(0, std::ios::beg);
  std::string data;
  data.resize(file_size);
  if_stream.read(data.data(), file_size);
  if (!if_stream) {
    return absl::UnknownError(
        absl::StrCat("Cannot read from file at '", path, "'"));
  }
  return data;
}
absl::StatusOr<tvs::VerifyReportRequest> GetGenoaV1ReportRequest() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  HATS_ASSIGN_OR_RETURN(oak::attestation::v1::Evidence evidence,
                        EvidenceFromFile(runfiles->Rlocation(
                            "_main/tvs/test_data/evidence_v1_genoa.txtpb")));
  tvs::VerifyReportRequest request;
  *request.mutable_evidence() = std::move(evidence);
  HATS_ASSIGN_OR_RETURN(*request.mutable_tee_certificate(),
                        ReadBinaryFile(runfiles->Rlocation(
                            "_main/tvs/test_data/vcek_genoa.crt")));
  return request;
}

absl::StatusOr<tvs::VerifyReportRequest> GetGenoaV2ReportRequest() {
  std::string runfiles_error;
  auto runfiles =
      bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&runfiles_error);
  if (runfiles == nullptr) {
    return absl::UnknownError(
        absl::StrCat("Runfiles::CreateForTest failed: ", runfiles_error));
  }
  HATS_ASSIGN_OR_RETURN(oak::attestation::v1::Evidence evidence,
                        EvidenceFromFile(runfiles->Rlocation(
                            "_main/tvs/test_data/evidence_v2_genoa.txtpb")));
  tvs::VerifyReportRequest request;
  *request.mutable_evidence() = std::move(evidence);
  HATS_ASSIGN_OR_RETURN(*request.mutable_tee_certificate(),
                        ReadBinaryFile(runfiles->Rlocation(
                            "_main/tvs/test_data/vcek_genoa.crt")));
  return request;
}

absl::StatusOr<tvs::AppraisalPolicies> GetTestAppraisalPolicies() {
  tvs::AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            policies {
              measurement {
                stage0_measurement {
                  amd_sev {
                    sha384: "c57729018b0a6fb90dc17bb138b0aa35e4401004283ff4a2c24d3739ff3750f52384370e77b7032862a08c440a9bc4dc"
                    min_tcb_version { boot_loader: 10 snp: 25 microcode: 84 }
                  }
                }
                kernel_image_sha256: "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447"
                kernel_setup_data_sha256: "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a"
                init_ram_fs_sha256: "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391"
                memory_map_sha256: "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe"
                acpi_table_sha256: "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e"
                kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
                system_image_sha256: "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836"
                container_binary_sha256: "b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899"
              }
              signature {
                signature: "db07413c03902c54275858269fb19aac96ba5d80f027653bc2664a87c37c277407bffa411e6b06de773cee60fd5bb7a0f7a01eda746fa8a508bbc2bdfd83c3b6"
                signer: "hats"
              }
            })pb",
          &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policies;
}

absl::StatusOr<std::string> GenerateTmpFile(absl::string_view content) {
  char filename[] = "/tmp/hatstest-XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1)
    return absl::FailedPreconditionError(
        absl::StrCat("mkstemp() failed: ", strerror(errno)));
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
  HATS_ASSERT_OK_AND_ASSIGN(std::string container_bundle_path,
                            GenerateTmpFile("container_bundle"));
  LauncherOakServer launcher_oak_service(
      /*oak_image_path=*/"", container_bundle_path, /*chunk_size=*/2);
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
  HATS_EXPECT_STATUS_GRPC(reader->Finish(),
                          absl::StatusCode::kDeadlineExceeded);
}

TEST(LauncherOakServer, GetContainerBundle) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string container_bundle_path,
                            GenerateTmpFile("container_bundle"));
  LauncherOakServer launcher_oak_service(
      /*oak_image_path=*/"", container_bundle_path, /*chunk_size=*/2);
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

  HATS_EXPECT_OK_GRPC(reader->Finish());
  EXPECT_EQ(result, "container_bundle");
}

TEST(LauncherOakServer, GetOakSystemImage) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string oak_image_path,
                            GenerateTmpFile("oak_image"));
  LauncherOakServer launcher_oak_service(
      oak_image_path, /*container_bundle_path=*/"", /*chunk_size=*/2);
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

  HATS_EXPECT_OK_GRPC(reader->Finish());
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
    // Macro can't set status code, should be FailedPreconditionError
    HATS_ASSIGN_OR_RETURN(
        rust::Box<tvs::TvsClient> tvs_client,
        tvs::NewTvsClient(StringViewToRustSlice(tvs_authentication_key_bytes),
                          StringViewToRustSlice(pub_key)),
        _.PrependWith("Failed to create trusted TVS client. "));
    HATS_ASSIGN_OR_RETURN(rust::Vec<uint8_t> initial_message,
                          tvs_client->BuildInitialMessage());
    std::unique_ptr<LauncherService::Stub> stub =
        LauncherService::NewStub(channel);
    auto context = std::make_unique<grpc::ClientContext>();
    std::unique_ptr<
        grpc::ClientReaderWriter<ForwardingTvsMessage, tvs::OpaqueMessage>>
        stream = stub->VerifyReport(context.get());

    tvs::OpaqueMessage opaque_message;
    opaque_message.set_binary_message(RustVecToString(initial_message));
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

    HATS_RETURN_IF_ERROR(
        tvs_client->ProcessHandshakeResponse(StringViewToRustSlice(
            orch_message.mutable_opaque_message()->binary_message())))
        .PrependWith("Failed to process handshake response: ");
    HATS_ASSIGN_OR_RETURN(
        rust::Vec<uint8_t> encrypted_command,
        tvs_client->BuildVerifyReportRequest(
            StringViewToRustSlice(
                verify_report_request.evidence().SerializeAsString()),
            StringViewToRustSlice(verify_report_request.tee_certificate()),
            std::string(application_signing_key)),
        _.PrependWith("Failed to process response: "));
    orch_message.mutable_opaque_message()->set_binary_message(
        RustVecToString(encrypted_command));
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
    HATS_ASSIGN_OR_RETURN(
        rust::Vec<uint8_t> secret,
        tvs_client->ProcessResponse(StringViewToRustSlice(
            orch_message.mutable_opaque_message()->binary_message())),
        _.PrependWith("Failed to process response: "));
    tvs::VerifyReportResponse response;
    if (!response.ParseFromArray(secret.data(), secret.size())) {
      return absl::UnknownError("Cannot parse result into proto");
    }
    response_vec.push_back(response);
  }
  return response_vec;
}

TEST(LauncherServer, Successful) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = "11",
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
      });

  // Declare the variables that will be set conditionally.
  tvs::AppraisalPolicies appraisal_policies;

#ifdef DYNAMIC_ATTESTATION
  HATS_ASSERT_OK_AND_ASSIGN(
      appraisal_policies, pcit::tvs::test_utils_cc::CreateDynamicGenoaPolicy());
#else
  HATS_ASSERT_OK_AND_ASSIGN(appraisal_policies, GetTestAppraisalPolicies());
#endif

  // Real TVS server.
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service,
      tvs::TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey, /*private_key_wrapping_keys=*/{},
      /*channel_map=*/
      std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>{
          {0, tvs_server->InProcessChannel(grpc::ChannelArguments())}},
      /*tee_certificate=*/"");
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c";

  HATS_ASSERT_OK_AND_ASSIGN(tvs::VerifyReportRequest verify_report_request,
                            GetGenoaV1ReportRequest());
  HATS_EXPECT_OK_AND_HOLDS(
      RemoteVerifyReport(
          std::unordered_map<int64_t, absl::string_view>{
              {0, tvs_primary_key.public_key_hex}},
          client_authentication_key.private_key_hex, kApplicationSigningKey,
          verify_report_request,
          launcher_server->InProcessChannel(grpc::ChannelArguments())),
      UnorderedElementsAre(EqualsProto(R"pb(
        secrets {
          key_id: "11"
          public_key: "public-1-1"
          private_key: "secret-1-1"
        })pb")));
}

TEST(LauncherServer, SplitSuccessful) {
  // Declare the variables that will be set conditionally.
  tvs::AppraisalPolicies appraisal_policies;

#ifdef DYNAMIC_ATTESTATION
  HATS_ASSERT_OK_AND_ASSIGN(
      appraisal_policies, pcit::tvs::test_utils_cc::CreateDynamicGenoaPolicy());
#else
  HATS_ASSERT_OK_AND_ASSIGN(appraisal_policies, GetTestAppraisalPolicies());
#endif

  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());

  // TVS Service 1.
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key1,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service1,
      tvs::TvsService::Create({
          .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
              tvs_primary_key1.private_key.GetStringView(),
              /*secondary_private_key=*/"",
              std::vector<key_manager::TestUserData>{
                  {
                      .user_id = "1",
                      .user_authentication_public_key =
                          client_authentication_key.public_key,
                      .key_id = "11",
                      .secret = "secret-1",
                      .public_key = "public-1",
                  },
              }),
          .appraisal_policies = appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  // TVS Service 2
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key2,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service2,
      tvs::TvsService::Create({
          .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
              tvs_primary_key2.private_key.GetStringView(),
              /*secondary_private_key=*/"",
              std::vector<key_manager::TestUserData>{
                  {
                      .user_id = "1",
                      .user_authentication_public_key =
                          client_authentication_key.public_key,
                      .key_id = "12",
                      .secret = "secret-2",
                      .public_key = "public-2",
                  },
              }),
          .appraisal_policies = appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  // TVS Service 3
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key3,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service3,
      tvs::TvsService::Create({
          .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
              tvs_primary_key3.private_key.GetStringView(),
              /*secondary_private_key=*/"",
              std::vector<key_manager::TestUserData>{
                  {
                      .user_id = "1",
                      .user_authentication_public_key =
                          client_authentication_key.public_key,
                      .key_id = "13",
                      .secret = "secret-3",
                      .public_key = "public-3",
                  },
              }),
          .appraisal_policies = appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> tvs_server1 =
      grpc::ServerBuilder().RegisterService(tvs_service1.get()).BuildAndStart();

  std::unique_ptr<grpc::Server> tvs_server2 =
      grpc::ServerBuilder().RegisterService(tvs_service2.get()).BuildAndStart();

  std::unique_ptr<grpc::Server> tvs_server3 =
      grpc::ServerBuilder().RegisterService(tvs_service3.get()).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey,
      /*private_key_wrapping_keys=*/{},
      /*channel_map=*/
      std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>{
          {0, tvs_server1->InProcessChannel(grpc::ChannelArguments())},
          // Intentionally flip the order.
          {2, tvs_server3->InProcessChannel(grpc::ChannelArguments())},
          {1, tvs_server2->InProcessChannel(grpc::ChannelArguments())},
      },
      /*tee_certificate=*/"");
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c";

  HATS_ASSERT_OK_AND_ASSIGN(tvs::VerifyReportRequest verify_report_request,
                            GetGenoaV1ReportRequest());
  // Currently we don't have a good way to change the secret because the
  // EchoKeyFetcher returns the same userID from every TVS
  HATS_EXPECT_OK_AND_HOLDS(
      RemoteVerifyReport(
          std::unordered_map<int64_t, absl::string_view>{
              {2, tvs_primary_key3.public_key_hex},
              {1, tvs_primary_key2.public_key_hex},
              {0, tvs_primary_key1.public_key_hex},
          },
          client_authentication_key.private_key_hex, kApplicationSigningKey,
          verify_report_request,
          launcher_server->InProcessChannel(grpc::ChannelArguments())),
      UnorderedElementsAre(EqualsProto(R"pb(
                             secrets {
                               key_id: "11"
                               public_key: "public-1"
                               private_key: "secret-1"
                             })pb"),
                           EqualsProto(R"pb(
                             secrets {
                               key_id: "12"
                               public_key: "public-2"
                               private_key: "secret-2"
                             })pb"),
                           EqualsProto(R"pb(
                             secrets {
                               key_id: "13"
                               public_key: "public-3"
                               private_key: "secret-3"
                             })pb")));
}

TEST(LauncherServer, BadReportError) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = "11",
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
      });
  HATS_ASSERT_OK_AND_ASSIGN(tvs::AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());
  // Real TVS server.
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service,
      tvs::TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey, PrivateKeyWrappingKeys{},
      /*channel_map=*/
      std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>{
          {0, tvs_server->InProcessChannel(grpc::ChannelArguments())}},
      /*tee_certificate=*/"");
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(tvs::VerifyReportRequest verify_report_request,
                            GetGenoaV2ReportRequest());

  constexpr absl::string_view kApplicationSigningKey =
      "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0";
  HATS_EXPECT_STATUS_MESSAGE(
      RemoteVerifyReport(
          std::unordered_map<int64_t, absl::string_view>{
              {0, tvs_primary_key.public_key_hex}},
          client_authentication_key.private_key_hex, kApplicationSigningKey,
          verify_report_request,
          launcher_server->InProcessChannel(grpc::ChannelArguments())),
      absl::StatusCode::kUnknown,
      AllOf(HasSubstr("Failed to verify report"),
            HasSubstr("No matching appraisal policy found")));
}

}  // namespace

}  // namespace pcit::client
