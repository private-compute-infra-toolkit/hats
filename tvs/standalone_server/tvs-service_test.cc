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
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_macros.h"
#include "status_macro/status_test_macros.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

ABSL_DECLARE_FLAG(std::string, appraisal_policy_file);

namespace privacy_sandbox::tvs {
namespace {

using ::google::protobuf::EqualsProto;
using ::testing::AllOf;
using ::testing::HasSubstr;

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
      "_main/tvs/test_data/good_verify_request_report.txtpb"));
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
      "_main/tvs/test_data/bad_verify_request_report.txtpb"));
}

absl::StatusOr<AppraisalPolicies> GetTestAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 11,
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 111,
              .secret = "secret-1-2",
              .public_key = "public-1-2",
          },
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 12,
              .secret = "secret-1-3",
              .public_key = "public-1-3",
          },
          {
              .user_id = 2,
              .user_authentication_public_key =
                  client_authentication_key2.public_key,
              .key_id = 100,
              .secret = "secret-2-1",
              .public_key = "public-2-1",
          },
          {
              .user_id = 3,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 101,
              .secret = "secret-3-1",
              .public_key = "public-3-1",
          },
          {
              .user_id = 4,
              .user_authentication_public_key = "00",
              .key_id = 103,
              .secret = "secret-4-1",
              .public_key = "public-4-1",
          },
          {
              .user_id = 5,
              .key_id = 104,
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
                            GetGoodReportRequest());
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

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
                key_id: 11
                public_key: "public-1-1"
                private_key: "secret-1-1"
              }
              secrets {
                key_id: 111
                public_key: "public-1-2"
                private_key: "secret-1-2"
              }
              secrets {
                key_id: 12
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
                key_id: 100
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 111,
              .secret = "secret-1-2",
              .public_key = "public-1-2",
          },
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 12,
              .secret = "secret-1-3",
              .public_key = "public-1-3",
          },
          {
              .user_id = 2,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 12,
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
                            GetGoodReportRequest());
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

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
              key_id: 11
              public_key: "public-1-1"
              private_key: "secret-1-1"
            }
            secrets {
              key_id: 111
              public_key: "public-1-2"
              private_key: "secret-1-2"
            }
            secrets {
              key_id: 12
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
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
                            GetBadReportRequest());
  const absl::string_view kApplicationSigningKey =
      "df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759";

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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
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
                            GetGoodReportRequest());

  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  HATS_ASSERT_OK_AND_HOLDS(
      tvs_client->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                            verify_report_request),
      EqualsProto(
          R"pb(
            secrets {
              key_id: 11
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 11,
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key.public_key,
              .key_id = 11,
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
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 11,
              .secret = "secret-1-1",
              .public_key = "public-1-1",
          },
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 111,
              .secret = "secret-1-2",
              .public_key = "public-1-2",
          },
          {
              .user_id = 1,
              .user_authentication_public_key =
                  client_authentication_key1.public_key,
              .key_id = 12,
              .secret = "secret-1-3",
              .public_key = "public-1-3",
          },
          {
              .user_id = 2,
              .user_authentication_public_key =
                  client_authentication_key2.public_key,
              .key_id = 100,
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
                            GetGoodReportRequest());
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

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
              key_id: 11
              public_key: "public-1-1"
              private_key: "secret-1-1"
            }
            secrets {
              key_id: 111
              public_key: "public-1-2"
              private_key: "secret-1-2"
            }
            secrets {
              key_id: 12
              public_key: "public-1-3"
              private_key: "secret-1-3"
            })pb"));
}

}  // namespace
}  // namespace privacy_sandbox::tvs
