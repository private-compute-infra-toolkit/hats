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
#include "crypto/ec-key.h"
#include "crypto/secret-data.h"
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
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/client/trusted-client.rs.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/untrusted_tvs/tvs-service.h"

namespace privacy_sandbox::client {
namespace {

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

struct TestEcKey {
  std::string private_key_hex;
  crypto::SecretData private_key;
  std::string public_key;
  std::string public_key_hex;
};

absl::StatusOr<TestEcKey> GenerateEcKey() {
  HATS_ASSIGN_OR_RETURN(std::unique_ptr<crypto::EcKey> ec_key,
                        crypto::EcKey::Create());

  HATS_ASSIGN_OR_RETURN(crypto::SecretData private_key,
                        ec_key->GetPrivateKey());

  HATS_ASSIGN_OR_RETURN(std::string public_key, ec_key->GetPublicKey());

  HATS_ASSIGN_OR_RETURN(std::string public_key_hex,
                        ec_key->GetPublicKeyInHex());

  return TestEcKey{
      .private_key_hex = absl::BytesToHexString(private_key.GetStringView()),
      .private_key = std::move(private_key),
      .public_key = std::move(public_key),
      .public_key_hex = std::move(public_key_hex),
  };
}

TEST(LauncherServer, Successful) {
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey tvs_primary_key, GenerateEcKey());
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey client_authentication_key,
                            GenerateEcKey());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
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
      /*tvs_authentication_key=*/kFakeKey, /*private_key_wrapping_keys=*/{},
      /*channel_map=*/
      std::unordered_map<int64_t, std::shared_ptr<grpc::Channel>>{
          {0, tvs_server->InProcessChannel(grpc::ChannelArguments())}},
      /*fetch_tee_certificate=*/true);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  HATS_ASSERT_OK_AND_ASSIGN(tvs::VerifyReportRequest verify_report_request,
                            GetGoodReportRequest());
  HATS_EXPECT_OK_AND_HOLDS(
      RemoteVerifyReport(
          std::unordered_map<int64_t, absl::string_view>{
              {0, tvs_primary_key.public_key_hex}},
          client_authentication_key.private_key_hex, kApplicationSigningKey,
          verify_report_request,
          launcher_server->InProcessChannel(grpc::ChannelArguments())),
      UnorderedElementsAre(EqualsProto(R"pb(
        secrets {
          key_id: 11
          public_key: "public-1-1"
          private_key: "secret-1-1"
        })pb")));
}

TEST(LauncherServer, SplitSuccessful) {
  HATS_ASSERT_OK_AND_ASSIGN(tvs::AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey client_authentication_key,
                            GenerateEcKey());

  // TVS Service 1.
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey tvs_primary_key1, GenerateEcKey());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service1,
      tvs::TvsService::Create({
          .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
              tvs_primary_key1.private_key.GetStringView(),
              /*secondary_private_key=*/"",
              std::vector<key_manager::TestUserData>{
                  {
                      .user_id = 1,
                      .user_authentication_public_key =
                          client_authentication_key.public_key,
                      .key_id = 11,
                      .secret = "secret-1",
                      .public_key = "public-1",
                  },
              }),
          .appraisal_policies = appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  // TVS Service 2
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey tvs_primary_key2, GenerateEcKey());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service2,
      tvs::TvsService::Create({
          .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
              tvs_primary_key2.private_key.GetStringView(),
              /*secondary_private_key=*/"",
              std::vector<key_manager::TestUserData>{
                  {
                      .user_id = 1,
                      .user_authentication_public_key =
                          client_authentication_key.public_key,
                      .key_id = 12,
                      .secret = "secret-2",
                      .public_key = "public-2",
                  },
              }),
          .appraisal_policies = appraisal_policies,
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  // TVS Service 3
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey tvs_primary_key3, GenerateEcKey());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<tvs::TvsService> tvs_service3,
      tvs::TvsService::Create({
          .key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
              tvs_primary_key3.private_key.GetStringView(),
              /*secondary_private_key=*/"",
              std::vector<key_manager::TestUserData>{
                  {
                      .user_id = 1,
                      .user_authentication_public_key =
                          client_authentication_key.public_key,
                      .key_id = 13,
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
      /*fetch_tee_certificate=*/true);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  HATS_ASSERT_OK_AND_ASSIGN(tvs::VerifyReportRequest verify_report_request,
                            GetGoodReportRequest());
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
                               key_id: 11
                               public_key: "public-1"
                               private_key: "secret-1"
                             })pb"),
                           EqualsProto(R"pb(
                             secrets {
                               key_id: 12
                               public_key: "public-2"
                               private_key: "secret-2"
                             })pb"),
                           EqualsProto(R"pb(
                             secrets {
                               key_id: 13
                               public_key: "public-3"
                               private_key: "secret-3"
                             })pb")));
}

TEST(LauncherServer, BadReportError) {
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey tvs_primary_key, GenerateEcKey());
  HATS_ASSERT_OK_AND_ASSIGN(TestEcKey client_authentication_key,
                            GenerateEcKey());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
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
      /*fetch_tee_certificate=*/true);
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(tvs::VerifyReportRequest verify_report_request,
                            GetBadReportRequest());

  constexpr absl::string_view kApplicationSigningKey =
      "df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759";
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

}  // namespace privacy_sandbox::client
