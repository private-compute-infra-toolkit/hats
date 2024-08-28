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

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
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
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"
#include "tvs/untrusted_tvs/tvs-server.h"

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
      "_main/tvs/test_data/good_verify_request_report.prototext"));
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
      "_main/tvs/test_data/bad_verify_request_report.prototext"));
}

absl::StatusOr<tvs::AppraisalPolicies> GetTestAppraisalPolicies() {
  oak::attestation::v1::ReferenceValues appraisal_policy;
  tvs::AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            policy {
              oak_containers {
                root_layer {
                  amd_sev {
                    stage0 { skip {} }
                    min_tcb_version { boot_loader: 7 snp: 15 microcode: 62 }
                  }
                }
                kernel_layer {
                  kernel {
                    digests {
                      image {
                        digests {
                          sha2_256: "D*6\221>.)\235\242\265\026\201D\203\266\254\357\021\266>\003\3675a\003A\250V\0223\367\277"
                        }
                      }
                      setup_data {
                        digests {
                          sha2_256: "h\313Bj\372\242\224e\367\307\037&\324\371\253Z\202\302\341\222b6d\213\354\"j\201\224C\035\271"
                        }
                      }
                    }
                  }
                  init_ram_fs {
                    digests {
                      digests {
                        sha2_256: ";0y=\1778\210t*\326?\023\353\346\240\003\274\233v4\231,dx\246\020\037\236\363#\265\256"
                      }
                    }
                  }
                  memory_map {
                    digests {
                      digests {
                        sha2_256: "L\230T(\375\306\020\034q\314&\335\303\023\315\202!\274\274TG\031\221\3549\261\276\002m\016\034("
                      }
                    }
                  }
                  acpi {
                    digests {
                      digests {
                        sha2_256: "\244\337\235\212d\334\271\247\023\316\300(\327\r+\025\231\372\357\007\314\320\320\341\201i1IkH\230\310"
                      }
                    }
                  }
                  kernel_cmd_line_text {
                    string_literals {
                      value: " console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10000000 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::eth0:off"
                    }
                  }
                }
                system_layer {
                  system_image {
                    digests {
                      digests {
                        sha2_256: "\343\336\331\347\317\331S\264\356cs\373\213A*v\276\020*n\335N\005\252\177\211p\342\013\374K\315"
                      }
                    }
                  }
                }
                container_layer {
                  binary {
                    digests {
                      digests {
                        sha2_256: "\277\027=\204ld\345\312\364\221\336\233^\242\337\2544\234\376\"\245\346\360:\330\004\213\270\n\336C\014"
                      }
                    }
                  }
                  configuration {
                    digests {
                      digests {
                        sha2_256: "\343\260\304B\230\374\034\024\232\373\364\310\231o\271$\'\256A\344d\233\223L\244\225\231\033xR\270U"
                      }
                    }
                  }
                }
              }
            })pb",
          &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policies;
}

constexpr absl::string_view kTvsPrivateKey =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr absl::string_view kTvsPublicKey =
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2"
    "fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
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

TEST(LauncherServer, Successful) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<tvs::AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());

  // Real TVS server.
  tvs::TvsServer tvs_service(*tvs_private_key, *std::move(appraisal_policies));

  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(&tvs_service).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  // Forwarding TVS server.
  LauncherServer launcher_service(
      /*tvs_authentication_key=*/kFakeKey,
      tvs_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";
  absl::StatusOr<std::unique_ptr<tvs::TvsUntrustedClient>> tvs_client =
      tvs::TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel =
              launcher_server->InProcessChannel(grpc::ChannelArguments()),
          .use_launcher_forwarding = true,
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<tvs::VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  EXPECT_THAT(
      (*tvs_client)
          ->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                      *verify_report_request),
      IsOkAndHolds(EqualsProto(
          R"pb(
            secrets {
              key_id: 64
              public_key: "1-public-key"
              private_key: "1-secret"
            })pb")));
}

TEST(LauncherServer, BadReportError) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<tvs::AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());

  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());
  // Real TVS server.
  tvs::TvsServer tvs_service(*tvs_private_key, /*secret=*/"",
                             *std::move(appraisal_policies));
  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(&tvs_service).BuildAndStart();

  // A key to be returned by the launcher service by `FetchOrchestratorMetadata`
  // rpc. We are not using this key in the test.
  constexpr absl::string_view kFakeKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  // Forwarding TVS server.
  LauncherServer launcher_service(
      /*tvs_authentication_key==*/kFakeKey,
      tvs_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<grpc::Server> launcher_server =
      grpc::ServerBuilder().RegisterService(&launcher_service).BuildAndStart();
  absl::StatusOr<std::unique_ptr<tvs::TvsUntrustedClient>> tvs_client =
      tvs::TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel =
              launcher_server->InProcessChannel(grpc::ChannelArguments()),
          .use_launcher_forwarding = true,
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<tvs::VerifyReportRequest> verify_report_request =
      GetBadReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  constexpr absl::string_view kApplicationSigningKey =
      "df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759";
  EXPECT_THAT(
      (*tvs_client)
          ->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                      *verify_report_request),
      StatusIs(absl::StatusCode::kUnknown,
               AllOf(HasSubstr("Failed to verify report"),
                     HasSubstr("No matching appraisal policy found"))));
}

}  // namespace

}  // namespace privacy_sandbox::client
