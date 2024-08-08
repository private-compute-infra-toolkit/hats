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

#include <fstream>

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"
#include "proto/attestation/reference_value.pb.h"
#include "tvs/appraisal_policies/policy-fetcher.h"

ABSL_DECLARE_FLAG(std::string, appraisal_policy_file);

namespace privacy_sandbox::tvs {
namespace {

using ::absl_testing::StatusIs;
using ::testing::HasSubstr;

constexpr absl::string_view kTestAppraisalPolicy = R"pb(
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
  })pb";

absl::StatusOr<std::string> WriteTestPolicyToFile() {
  std::string test_file = absl::StrCat(testing::TempDir(), "policy_file");
  std::ofstream policy_file(test_file);
  if (!policy_file.is_open()) {
    return absl::FailedPreconditionError("Cannot open a file");
  }
  policy_file << kTestAppraisalPolicy;
  policy_file.close();
  return test_file;
}

absl::StatusOr<oak::attestation::v1::ReferenceValues> GetTestAppraisalPolicy() {
  oak::attestation::v1::ReferenceValues appraisal_policy;
  if (!google::protobuf::TextFormat::ParseFromString(kTestAppraisalPolicy,
                                                     &appraisal_policy)) {
    return absl::UnknownError("Cannot parse test appraisal policy");
  }
  return appraisal_policy;
}

TEST(PolicyFetcherLocal, Normal) {
  absl::StatusOr<std::string> policy_file = WriteTestPolicyToFile();
  ASSERT_TRUE(policy_file.ok());
  absl::StatusOr<oak::attestation::v1::ReferenceValues> expected_policy =
      GetTestAppraisalPolicy();
  ASSERT_TRUE(expected_policy.ok());
  absl::SetFlag(&FLAGS_appraisal_policy_file, *policy_file);
  absl::StatusOr<std::unique_ptr<PolicyFetcher>> policy_fetcher =
      PolicyFetcher::Create();
  ASSERT_TRUE(policy_fetcher.ok());
  absl::StatusOr<oak::attestation::v1::ReferenceValues> policy =
      (*policy_fetcher)->GetPolicy(/*policy_id=*/"");
  ASSERT_TRUE(policy.ok());
  EXPECT_EQ(policy->SerializeAsString(), expected_policy->SerializeAsString());
}

TEST(PolicyFetcherLocal, CreateError) {
  absl::SetFlag(&FLAGS_appraisal_policy_file, "nonexistent");
  EXPECT_THAT(PolicyFetcher::Create(),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       "Failed to open: nonexistent"));
}

}  // namespace
}  // namespace privacy_sandbox::tvs
