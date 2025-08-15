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

#include "tvs/standalone_server/tvs-service.h"

#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crypto/test-ec-key.h"
#include "gmock/gmock.h"
#include "google/protobuf/text_format.h"
#include "grpcpp/client_context.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "grpcpp/support/sync_stream.h"
#include "gtest/gtest.h"
#include "key_manager/test-key-fetcher.h"
#include "proto/attestation/evidence.pb.h"
#include "src/google/protobuf/io/zero_copy_stream_impl.h"
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

ABSL_DECLARE_FLAG(std::string, appraisal_policy_file);

namespace pcit::tvs {
namespace {

using ::google::protobuf::EqualsProto;
using ::testing::AllOf;
using ::testing::HasSubstr;

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

absl::StatusOr<VerifyReportRequest> GetGenoaV1ReportRequest() {
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
  VerifyReportRequest request;
  *request.mutable_evidence() = std::move(evidence);
  HATS_ASSIGN_OR_RETURN(*request.mutable_tee_certificate(),
                        ReadBinaryFile(runfiles->Rlocation(
                            "_main/tvs/test_data/vcek_genoa.crt")));
  return request;
}

absl::StatusOr<VerifyReportRequest> GetGenoaV2ReportRequest() {
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
  VerifyReportRequest request;
  *request.mutable_evidence() = std::move(evidence);
  HATS_ASSIGN_OR_RETURN(*request.mutable_tee_certificate(),
                        ReadBinaryFile(runfiles->Rlocation(
                            "_main/tvs/test_data/vcek_genoa.crt")));
  return request;
}

absl::StatusOr<AppraisalPolicies> GetTestAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
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

TEST(TvsService, Successful) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key1,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key2,
                            crypto::GenerateEcKeyForTest());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "11",
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "111",
              .secret = "secret-1-2",
              .public_key = "public-1-2",
          },
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "12",
              .secret = "secret-1-3",
              .public_key = "public-1-3",
          },
          {
              .user_id = "2",
              .user_authentication_public_key =
                  client_authentication_key2.public_key,
              .key_id = "100",
              .secret = "secret-2-1",
              .public_key = "public-2-1",
          },
          {
              .user_id = "3",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "101",
              .secret = "secret-3-1",
              .public_key = "public-3-1",
          },
          {
              .user_id = "4",
              .user_authentication_public_key = "00",
              .key_id = "103",
              .secret = "secret-4-1",
              .public_key = "public-4-1",
          },
          {
              .user_id = "5",
              .key_id = "104",
              .secret = "secret-5-1",
              .public_key = "public-5-1",
          },
      });

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsService> tvs_service,
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(VerifyReportRequest verify_report_request,
                            GetGenoaV1ReportRequest());
  constexpr absl::string_view kApplicationSigningKey =
      "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c";

  {
    HATS_ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<TvsUntrustedClient> tvs_client,
        TvsUntrustedClient::CreateClient({
            .tvs_public_key = tvs_primary_key.public_key_hex,
            .tvs_authentication_key =
                std::move(client_authentication_key1.private_key_hex),
            .channel = server->InProcessChannel(grpc::ChannelArguments()),
        }));

    HATS_EXPECT_OK_AND_HOLDS(
        tvs_client->VerifyReportAndGetSecrets(
            std::string(kApplicationSigningKey), verify_report_request),
        EqualsProto(
            R"pb(
              secrets {
                key_id: "11"
                public_key: "public-1-1"
                private_key: "secret-1-1"
              }
              secrets {
                key_id: "111"
                public_key: "public-1-2"
                private_key: "secret-1-2"
              }
              secrets {
                key_id: "12"
                public_key: "public-1-3"
                private_key: "secret-1-3"
              })pb"));
  }
  {
    HATS_ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<TvsUntrustedClient> tvs_client,
        TvsUntrustedClient::CreateClient({
            .tvs_public_key = tvs_primary_key.public_key_hex,
            .tvs_authentication_key =
                std::move(client_authentication_key2.private_key_hex),
            .channel = server->InProcessChannel(grpc::ChannelArguments()),
        }));

    HATS_EXPECT_OK_AND_HOLDS(
        tvs_client->VerifyReportAndGetSecrets(
            std::string(kApplicationSigningKey), verify_report_request),
        EqualsProto(
            R"pb(
              secrets {
                key_id: "100"
                public_key: "public-2-1"
                private_key: "secret-2-1"
              })pb"));
  }
}

TEST(TvsService, UseSecondaryTvsKey) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_secondary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key,
                            crypto::GenerateEcKeyForTest());

  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      tvs_secondary_key.private_key.GetStringView(),
      std::vector<key_manager::TestUserData>{
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = "11",
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = "111",
              .secret = "secret-1-2",
              .public_key = "public-1-2",
          },
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = "12",
              .secret = "secret-1-3",
              .public_key = "public-1-3",
          },
          {
              .user_id = "2",
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = "12",
              .secret = "secret-2-1",
              .public_key = "public-2-1",
          },
      });

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());
  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsService> tvs_service,
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(VerifyReportRequest verify_report_request,
                            GetGenoaV1ReportRequest());
  constexpr absl::string_view kApplicationSigningKey =
      "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c";

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsUntrustedClient> tvs_client,
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = tvs_secondary_key.public_key_hex,
          .tvs_authentication_key =
              std::move(client_authentication_key.private_key_hex),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }));

  HATS_EXPECT_OK_AND_HOLDS(
      tvs_client->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                            verify_report_request),
      EqualsProto(
          R"pb(
            secrets {
              key_id: "11"
              public_key: "public-1-1"
              private_key: "secret-1-1"
            }
            secrets {
              key_id: "111"
              public_key: "public-1-2"
              private_key: "secret-1-2"
            }
            secrets {
              key_id: "12"
              public_key: "public-1-3"
              private_key: "secret-1-3"
            })pb"));
}

TEST(TvsService, BadReportError) {
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

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsService> tvs_service,
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsUntrustedClient> tvs_client,
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = tvs_primary_key.public_key_hex,
          .tvs_authentication_key =
              std::move(client_authentication_key).private_key_hex,
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }));

  HATS_ASSERT_OK_AND_ASSIGN(VerifyReportRequest verify_report_request,
                            GetGenoaV2ReportRequest());
  const absl::string_view kApplicationSigningKey =
      "90c6593892237eb36a525902340c02a6865a13e37ed9eb73b5123b312a0bb3b0";

  HATS_EXPECT_STATUS_MESSAGE(
      tvs_client->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                            verify_report_request),
      absl::StatusCode::kUnknown,
      AllOf(HasSubstr("Failed to verify report"),
            HasSubstr("No matching appraisal policy found")));
}

TEST(TvsService, SessionTerminationAfterVerifyReportRequest) {
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

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsService> tvs_service,
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsUntrustedClient> tvs_client,
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = tvs_primary_key.public_key_hex,
          .tvs_authentication_key = client_authentication_key.private_key_hex,
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }));

  HATS_ASSERT_OK_AND_ASSIGN(VerifyReportRequest verify_report_request,
                            GetGenoaV1ReportRequest());

  constexpr absl::string_view kApplicationSigningKey =
      "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c";

  HATS_ASSERT_OK_AND_HOLDS(
      tvs_client->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                            verify_report_request),
      EqualsProto(
          R"pb(
            secrets {
              key_id: "11"
              public_key: "public-1-1"
              private_key: "secret-1-1"
            })pb"));

  HATS_EXPECT_STATUS_MESSAGE(
      tvs_client->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                            verify_report_request),
      absl::StatusCode::kUnknown,
      HasSubstr("Failed to write message to stream."));
}

TEST(TvsService, MalformedMessageError) {
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
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsService> tvs_service,
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();
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
              HasSubstr("Invalid or malformed command"));
}

TEST(TvsService, CreatingTrustedTvsServiceError) {
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      /*primary_private_key=*/"000",
      /*secondary_private_key=*/"",
      /*user_data=*/std::vector<key_manager::TestUserData>{});
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());

  HATS_EXPECT_STATUS_MESSAGE(
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }),
      absl::StatusCode::kFailedPrecondition,
      AllOf(HasSubstr("Cannot create trusted TVS server"),
            HasSubstr("Invalid primary private key. Key should be 32 bytes "
                      "long.")));
}

TEST(TvsService, AuthenticationError) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key1,
                            crypto::GenerateEcKeyForTest());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "11",
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
      });
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetTestAppraisalPolicies());

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsService> tvs_service,
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key2,
                            crypto::GenerateEcKeyForTest());
  HATS_EXPECT_STATUS_MESSAGE(
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = tvs_primary_key.public_key_hex,
          .tvs_authentication_key =
              std::move(client_authentication_key2).private_key_hex,
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }),
      absl::StatusCode::kUnknown,
      HasSubstr("UNAUTHENTICATED: unregistered or expired public key"));
}

absl::StatusOr<AppraisalPolicies> GetInsecureAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            policies {
              measurement {
                stage0_measurement { insecure {} }
                kernel_image_sha256: "eca5ef41f6dc7e930d8e9376e78d19802c49f5a24a14c0be18c8e0e3a8be3e84"
                kernel_setup_data_sha256: "c1022e7dd178023609a24839d1c32ea2687477586a5442b9209b67f73655b11c"
                init_ram_fs_sha256: "5e26c78994236a661a4b522e07e8b8c9706ffc1005d8c4f5ccb5d0c641de1edb"
                memory_map_sha256: "73ec5878eed10ac257e855324bf2621ebed8f5825464c6afe2f0152ac23ea7fb"
                acpi_table_sha256: "668b5b4db79f9939c741d62182b5962e19c150c1eb78fa824864feb299c0e8c7"
                kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
                system_image_sha256: "bb3bdaa18daa6a6bcb90cc00ca7213c20cefec9b894f612baeafd569281766e1"
                container_binary_sha256: "cb31d889e33eaf9e3b43cdbeb3554903c36b5e037c5187e876a69e8c5b5d864c"
              }
              signature {
                signature: "82422b8c775c51498fab8252c956597e88ba6d6f7045c9815c08b617f4302c70a748a911222e241fad516113307a695d62d65cde98916c094b634d047dc22d60"
                signer: "hats"
              }
            })pb",
          &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policies;
}

// Passing insecure policies in a secure mode.
TEST(TvsService, InsecurePoliciesError) {
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
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies appraisal_policies,
                            GetInsecureAppraisalPolicies());
  HATS_EXPECT_STATUS_MESSAGE(
      TvsService::Create({
          .key_fetcher = std::move(key_fetcher),
          .appraisal_policies = std::move(appraisal_policies),
          .enable_policy_signature = true,
          .accept_insecure_policies = false,
      }),
      absl::StatusCode::kFailedPrecondition,
      AllOf(HasSubstr("Cannot create trusted TVS server"),
            HasSubstr("Cannot accept insecure policies")));
}

absl::StatusOr<std::string> WriteTestPolicyToFile(
    absl::string_view appraisal_policies) {
  std::string test_file = absl::StrCat(testing::TempDir(), "policy_file");
  std::ofstream policy_file(test_file);
  if (!policy_file.is_open()) {
    return absl::FailedPreconditionError("Cannot open a file");
  }
  policy_file << appraisal_policies;
  policy_file.close();
  return test_file;
}

TEST(TvsService, DynamicPolicyFetching) {
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey tvs_primary_key,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key1,
                            crypto::GenerateEcKeyForTest());
  HATS_ASSERT_OK_AND_ASSIGN(crypto::TestEcKey client_authentication_key2,
                            crypto::GenerateEcKeyForTest());
  auto key_fetcher = std::make_unique<key_manager::TestKeyFetcher>(
      tvs_primary_key.private_key.GetStringView(),
      /*secondary_private_key=*/"",
      std::vector<key_manager::TestUserData>{
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "11",
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "111",
              .secret = "secret-1-2",
              .public_key = "public-1-2",
          },
          {
              .user_id = "1",
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = "12",
              .secret = "secret-1-3",
              .public_key = "public-1-3",
          },
          {
              .user_id = "2",
              .user_authentication_public_key =
                  client_authentication_key2.public_key,
              .key_id = "100",
              .secret = "secret-2-1",
              .public_key = "public-2-1",
          },
      });

  // In dynamic policy fetching mode, only policies that are matching the
  // application layer digest are fetched and proceeded. To test that TVS is
  // using dynamic policy fetching, we pass two policies: one is accepted
  // (secure) and one should be rejected (insecure). The two policies have
  // different application layer digest. If dynamic policy fetching is enabled,
  // then the second policy should not be fetched. If you change
  // `container_binary_sha256` for the second policy to match the first one,
  // this test should fail. As it would indicate that TrustedTvs tried to
  // process both policies and it should reject the second one since we asked it
  // to only accept secure policies.
  HATS_ASSERT_OK_AND_ASSIGN(
      std::string policy_file,
      WriteTestPolicyToFile(
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
            }
            policies {
              measurement {
                stage0_measurement { insecure {} }
                kernel_image_sha256: "eca5ef41f6dc7e930d8e9376e78d19802c49f5a24a14c0be18c8e0e3a8be3e84"
                kernel_setup_data_sha256: "c1022e7dd178023609a24839d1c32ea2687477586a5442b9209b67f73655b11c"
                init_ram_fs_sha256: "5e26c78994236a661a4b522e07e8b8c9706ffc1005d8c4f5ccb5d0c641de1edb"
                memory_map_sha256: "73ec5878eed10ac257e855324bf2621ebed8f5825464c6afe2f0152ac23ea7fb"
                acpi_table_sha256: "668b5b4db79f9939c741d62182b5962e19c150c1eb78fa824864feb299c0e8c7"
                kernel_cmd_line_regex: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
                system_image_sha256: "bb3bdaa18daa6a6bcb90cc00ca7213c20cefec9b894f612baeafd569281766e1"
                container_binary_sha256: "cb31d889e33eaf9e3b43cdbeb3554903c36b5e037c5187e876a69e8c5b5d864c"
              }
              signature {
                signature: "82422b8c775c51498fab8252c956597e88ba6d6f7045c9815c08b617f4302c70a748a911222e241fad516113307a695d62d65cde98916c094b634d047dc22d60"
                signer: "hats"
              }
            })pb"));

  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<TvsService> tvs_service,
                            TvsService::Create({
                                .key_fetcher = std::move(key_fetcher),
                                .policy_fetcher = std::move(policy_fetcher),
                                .enable_policy_signature = true,
                                .accept_insecure_policies = false,
                            }));

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(tvs_service.get()).BuildAndStart();

  HATS_ASSERT_OK_AND_ASSIGN(VerifyReportRequest verify_report_request,
                            GetGenoaV1ReportRequest());
  constexpr absl::string_view kApplicationSigningKey =
      "be828103ab28b93a5d91592d69374541d6e7decd287ef7df1f990a87f231cb8c";

  HATS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<TvsUntrustedClient> tvs_client,
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = tvs_primary_key.public_key_hex,
          .tvs_authentication_key =
              std::move(client_authentication_key1.private_key_hex),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }));

  HATS_EXPECT_OK_AND_HOLDS(
      tvs_client->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                            verify_report_request),
      EqualsProto(
          R"pb(
            secrets {
              key_id: "11"
              public_key: "public-1-1"
              private_key: "secret-1-1"
            }
            secrets {
              key_id: "111"
              public_key: "public-1-2"
              private_key: "secret-1-2"
            }
            secrets {
              key_id: "12"
              public_key: "public-1-3"
              private_key: "secret-1-3"
            })pb"));
}

}  // namespace
}  // namespace pcit::tvs
