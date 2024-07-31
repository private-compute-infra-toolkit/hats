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

#include "client/launcher/forwarding-tvs-server.h"

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
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "grpcpp/support/channel_arguments.h"
#include "grpcpp/support/status.h"
#include "gtest/gtest.h"
#include "proto/attestation/reference_value.pb.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"
#include "tvs/untrusted_tvs/tvs-server.h"

namespace privacy_sandbox::tvs {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::StrEq;

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
            })pb",
          &appraisal_policy)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policy;
}

constexpr absl::string_view kTvsPrivateKey =
    "0000000000000000000000000000000000000000000000000000000000000001";
constexpr absl::string_view kTvsPublicKey =
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2"
    "fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
constexpr absl::string_view kSecret = "secret";

TEST(ForwardingTvsServer, Successful) {
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(appraisal_policy.ok());
  // Real TVS server.
  TvsServer tvs_service(std::string(kTvsPrivateKey), std::string(kSecret),
                        *std::move(appraisal_policy));
  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(&tvs_service).BuildAndStart();

  // Forwarding TVS server.
  ForwardingTvsServer forwarding_tvs_service(
      tvs_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<grpc::Server> forwarding_tvs_server =
      grpc::ServerBuilder()
          .RegisterService(&forwarding_tvs_service)
          .BuildAndStart();
  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .channel =
              forwarding_tvs_server->InProcessChannel(grpc::ChannelArguments()),
          .use_launcher_forwarding = true,
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  EXPECT_THAT((*tvs_client)
                  ->VerifyReportAndGetToken(std::string(kApplicationSigningKey),
                                            *verify_report_request),
              IsOkAndHolds(StrEq(kSecret)));
}

TEST(ForwardingTvsServer, BadReportError) {
  absl::StatusOr<oak::attestation::v1::ReferenceValues> appraisal_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(appraisal_policy.ok());

  // Real TVS server.
  TvsServer tvs_service(std::string(kTvsPrivateKey), /*secret=*/"",
                        *std::move(appraisal_policy));
  std::unique_ptr<grpc::Server> tvs_server =
      grpc::ServerBuilder().RegisterService(&tvs_service).BuildAndStart();

  // Forwarding TVS server.
  ForwardingTvsServer forwarding_tvs_service(
      tvs_server->InProcessChannel(grpc::ChannelArguments()));
  std::unique_ptr<grpc::Server> forwarding_tvs_server =
      grpc::ServerBuilder()
          .RegisterService(&forwarding_tvs_service)
          .BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .channel =
              forwarding_tvs_server->InProcessChannel(grpc::ChannelArguments()),
          .use_launcher_forwarding = true,
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetBadReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  constexpr absl::string_view kApplicationSigningKey =
      "df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759";
  EXPECT_THAT((*tvs_client)
                  ->VerifyReportAndGetToken(std::string(kApplicationSigningKey),
                                            *verify_report_request),
              StatusIs(absl::StatusCode::kUnknown,
                       AllOf(HasSubstr("Failed to verify report"),
                             HasSubstr("system layer verification failed"))));
}

}  // namespace

}  // namespace privacy_sandbox::tvs
