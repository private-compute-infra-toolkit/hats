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
#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"

ABSL_DECLARE_FLAG(std::string, appraisal_policy_file);

namespace privacy_sandbox::tvs {
namespace {

using ::absl_testing::StatusIs;
using ::testing::HasSubstr;

constexpr absl::string_view kTestAppraisalPolicies = R"pb(
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
  })pb";

absl::StatusOr<std::string> WriteTestPolicyToFile() {
  std::string test_file = absl::StrCat(testing::TempDir(), "policy_file");
  std::ofstream policy_file(test_file);
  if (!policy_file.is_open()) {
    return absl::FailedPreconditionError("Cannot open a file");
  }
  policy_file << kTestAppraisalPolicies;
  policy_file.close();
  return test_file;
}

absl::StatusOr<AppraisalPolicies> GetTestAppraisalPolicies() {
  AppraisalPolicies policies;
  if (!google::protobuf::TextFormat::ParseFromString(kTestAppraisalPolicies,
                                                     &policies)) {
    return absl::UnknownError("Cannot parse test appraisal policies");
  }
  return policies;
}

TEST(PolicyFetcherLocal, Normal) {
  absl::StatusOr<std::string> policy_file = WriteTestPolicyToFile();
  ASSERT_TRUE(policy_file.ok());
  absl::StatusOr<AppraisalPolicies> expected_policies =
      GetTestAppraisalPolicies();
  ASSERT_TRUE(expected_policies.ok());
  absl::SetFlag(&FLAGS_appraisal_policy_file, *policy_file);
  absl::StatusOr<std::unique_ptr<PolicyFetcher>> policy_fetcher =
      PolicyFetcher::Create();
  ASSERT_TRUE(policy_fetcher.ok());
  absl::StatusOr<AppraisalPolicies> policies =
      (*policy_fetcher)->GetLatestNPolicies(/*n=*/1);
  ASSERT_TRUE(policies.ok());
  EXPECT_EQ(policies->SerializeAsString(),
            expected_policies->SerializeAsString());
}

TEST(PolicyFetcherLocal, CreateError) {
  absl::SetFlag(&FLAGS_appraisal_policy_file, "nonexistent");
  EXPECT_THAT(PolicyFetcher::Create(),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       "Failed to open: nonexistent"));
}

}  // namespace
}  // namespace privacy_sandbox::tvs
