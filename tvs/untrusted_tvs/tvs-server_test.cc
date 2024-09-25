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

#include "tvs/untrusted_tvs/tvs-server.h"

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
#include "key_manager/key-fetcher-wrapper.h"
#include "src/google/protobuf/test_textproto.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "tvs/proto/appraisal_policies.pb.h"
#include "tvs/proto/tvs_messages.pb.h"
#include "tvs/test_client/tvs-untrusted-client.h"

namespace privacy_sandbox::tvs {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
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
      "_main/tvs/test_data/good_verify_request_report.textproto"));
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
      "_main/tvs/test_data/bad_verify_request_report.textproto"));
}

absl::StatusOr<AppraisalPolicies> GetTestAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            signed_policy {
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
              }
              signature: {
                signature: "\x8f\xaa?\xda\xd7[_W\x17\xd4\xaf\xa0\xa7\x13\xc0\x0c\x0b\x8d%\xe0\xbbK\xebGa\xb2\x01\xa8\xd1\xe6\xbf\x04\x89\xaf\xd5\xc1Wg,\x03\x0f\xb2\xc8\x8e\xcc\xbe\xbc\xc2(\x83\x8a!\x94\xf9)\x013\x9d\xdfu\xaf\x9fK\xae"
                signer: ""
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

TEST(TvsServer, Successful) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());

  TvsServer tvs_server(*tvs_private_key, *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

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

TEST(TvsServer, BadReportError) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());

  TvsServer tvs_server(*tvs_private_key, *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetBadReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  const absl::string_view kApplicationSigningKey =
      "df2eb4193f689c0fd5a266d764b8b6fd28e584b4f826a3ccb96f80fed2949759";
  EXPECT_THAT(
      (*tvs_client)
          ->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                      *verify_report_request),
      StatusIs(absl::StatusCode::kUnknown,
               AllOf(HasSubstr("Failed to verify report"),
                     HasSubstr("No matching appraisal policy found"))));
}

TEST(TvsServer, SessionTerminationAfterVerifyReportRequest) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());

  TvsServer tvs_server(*tvs_private_key, *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);

  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  absl::StatusOr<std::unique_ptr<TvsUntrustedClient>> tvs_client =
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      });
  ASSERT_TRUE(tvs_client.ok());

  absl::StatusOr<VerifyReportRequest> verify_report_request =
      GetGoodReportRequest();
  ASSERT_TRUE(verify_report_request.ok());

  constexpr absl::string_view kApplicationSigningKey =
      "b4f9b8837978fe99a99e55545c554273d963e1c73e16c7406b99b773e930ce23";

  ASSERT_THAT(
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

  EXPECT_THAT(
      (*tvs_client)
          ->VerifyReportAndGetSecrets(std::string(kApplicationSigningKey),
                                      *verify_report_request),
      StatusIs(absl::StatusCode::kUnknown,
               HasSubstr("Failed to write message to stream.")));
}

TEST(TvsServer, MalformedMessageError) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());

  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());

  TvsServer tvs_server(*tvs_private_key, *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);
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
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  TvsServer tvs_server("0000", *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  EXPECT_THAT(
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }),
      StatusIs(
          absl::StatusCode::kUnknown,
          AllOf(HasSubstr("Cannot create trusted TVS server"),
                HasSubstr("Invalid primary private key. Key should be 32 bytes "
                          "long."))));
}

TEST(TvsServer, AuthenticationError) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  absl::StatusOr<std::string> tvs_private_key =
      HexStringToBytes(kTvsPrivateKey);
  ASSERT_TRUE(tvs_private_key.ok());

  TvsServer tvs_server(*tvs_private_key, *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  constexpr absl::string_view kBadAuthenticationKey =
      "4583ed91df564f17c0726f7fa4d7e00ec2da067ad3c92448794c5982f6150ba7";
  EXPECT_THAT(TvsUntrustedClient::CreateClient({
                  .tvs_public_key = std::string(kTvsPublicKey),
                  .tvs_authentication_key = std::string(kBadAuthenticationKey),
                  .channel = server->InProcessChannel(grpc::ChannelArguments()),
              }),
              StatusIs(absl::StatusCode::kUnknown,
                       HasSubstr("Unauthenticated: Failed to lookup user")));
}

absl::StatusOr<AppraisalPolicies> GetInsecureAppraisalPolicies() {
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::ParseFromString(
          R"pb(
            signed_policy {
              policy {
                oak_containers {
                  root_layer { insecure {} }
                  kernel_layer {
                    kernel {
                      digests {
                        image {
                          digests {
                            sha2_256: "\354\245\357A\366\334~\223\r\216\223v\347\215\031\200,I\365\242J\024\300\276\030\310\340\343\250\276>\204"
                          }
                        }
                        setup_data {
                          digests {
                            sha2_256: "\301\002.}\321x\0026\t\242H9\321\303.\242htwXjTB\271 \233g\3676U\261\034"
                          }
                        }
                      }
                    }
                    init_ram_fs {
                      digests {
                        digests {
                          sha2_256: "^&\307\211\224#jf\032KR.\007\350\270\311po\374\020\005\330\304\365\314\265\320\306A\336\036\333"
                        }
                      }
                    }
                    memory_map {
                      digests {
                        digests {
                          sha2_256: "s\354Xx\356\321\n\302W\350U2K\362b\036\276\330\365\202Td\306\257\342\360\025*\302>\247\373"
                        }
                      }
                    }
                    acpi {
                      digests {
                        digests {
                          sha2_256: "f\213[M\267\237\2319\307A\326!\202\265\226.\031\301P\301\353x\372\202Hd\376\262\231\300\350\307"
                        }
                      }
                    }
                    kernel_cmd_line_text {
                      regex {
                        value: "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 brd.max_part=1 ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- --launcher-addr=vsock://2:.*$"
                      }
                    }
                  }
                  system_layer {
                    system_image {
                      digests {
                        digests {
                          sha2_256: "\342\311aW\254\341|\224\020\2321\2355\370z\256=\302\007\353W\035\252\337\326\324 ]\273C\360w"
                        }
                      }
                    }
                  }
                  container_layer {
                    binary {
                      digests {
                        digests {
                          sha2_256: "\3131\330\211\343>\257\236;C\315\276\263UI\003\303k^\003|Q\207\350v\246\236\214[]\206L"
                        }
                      }
                    }
                    configuration { skip {} }
                  }
                }
              }
              signature {
                signature: "\xa4<\x9e\x89\xf1Lr\x06+\x14\xdf\xb0\xd5\x0b\xb1\xd4\x0e\\a\xbe/\xa4\x8e\xd6!C\x86\xed}L\x908\t\xfb\xee[L\x9c\x15^l\xdc\xd0\n5>\xb8Hr\x91\xba#\x9a\x85\xf7\xd1\x81\xd8\t+\xb3;_\xb3"
                signer: ""
              }
            })pb",
          &appraisal_policies)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policies;
}

// Passing insecure policies in a secure mode.
TEST(TvsServer, InsecurePoliciesError) {
  key_manager::RegisterEchoKeyFetcherForTest();
  absl::StatusOr<AppraisalPolicies> appraisal_policies =
      GetInsecureAppraisalPolicies();
  ASSERT_TRUE(appraisal_policies.ok());
  TvsServer tvs_server("0000", *std::move(appraisal_policies),
                       /*enable_policy_signature=*/true,
                       /*accept_insecure_policies=*/false);
  std::unique_ptr<grpc::Server> server =
      grpc::ServerBuilder().RegisterService(&tvs_server).BuildAndStart();

  EXPECT_THAT(
      TvsUntrustedClient::CreateClient({
          .tvs_public_key = std::string(kTvsPublicKey),
          .tvs_authentication_key = std::string(kTvsAuthenticationKey),
          .channel = server->InProcessChannel(grpc::ChannelArguments()),
      }),
      StatusIs(
          absl::StatusCode::kUnknown,
          AllOf(HasSubstr("Cannot create trusted TVS server"),
                HasSubstr("Invalid primary private key. Key should be 32 bytes "
                          "long."))));
}
}  // namespace
}  // namespace privacy_sandbox::tvs
