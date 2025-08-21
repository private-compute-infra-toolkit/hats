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

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <string>

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "gmock/gmock.h"
#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"
#include "openssl/sha.h"
#include "src/google/protobuf/test_textproto.h"
#include "status_macro/status_test_macros.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"

ABSL_DECLARE_FLAG(std::string, appraisal_policy_file);
ABSL_DECLARE_FLAG(std::string, stage0_blob_directory);

namespace pcit::tvs {
namespace {

using ::google::protobuf::EqualsProto;
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
      container_binary_sha256: [
        "bf173d846c64e5caf491de9b5ea2dfac349cfe22a5e6f03ad8048bb80ade430c",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      ]
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

struct TestBlobInfo {
  std::string directory_path;
  std::string blob_sha256_digest;
  std::string blob_data;
};

absl::StatusOr<TestBlobInfo> CreateTestBlobDirectory() {
  TestBlobInfo info;
  info.blob_data = "fake_blob_data";

  // Calculate the real hash of the fake data
  std::string blob_sha_raw(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const unsigned char*>(info.blob_data.data()),
         info.blob_data.size(),
         reinterpret_cast<unsigned char*>(blob_sha_raw.data()));
  info.blob_sha256_digest = absl::BytesToHexString(blob_sha_raw);

  // Create a temporary directory using the POSIX mkdir function
  info.directory_path = absl::StrCat(testing::TempDir(), "/test_blob_dir");
  // '0755' sets the directory permissions.
  if (mkdir(info.directory_path.c_str(), 0755) != 0) {
    if (errno != EEXIST) {
      return absl::InternalError("Failed to create test blob directory");
    }
  }

  // Create the blob file inside the directory, named with its hash
  std::string blob_file_path =
      absl::StrCat(info.directory_path, "/", info.blob_sha256_digest);
  std::ofstream blob_file(blob_file_path, std::ios::binary);
  if (!blob_file.is_open()) {
    return absl::InternalError("Failed to create test blob file");
  }
  blob_file << info.blob_data;
  blob_file.close();

  return info;
}

TEST(PolicyFetcherLocal, GetLatestNPoliciesSuccessfull) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string policy_file, WriteTestPolicyToFile());
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());
  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  HATS_EXPECT_OK_AND_HOLDS(policy_fetcher->GetLatestNPolicies(/*n=*/1),
                           EqualsProto(kTestAppraisalPolicies));
}

TEST(PolicyFetcherLocal, GetLatestNPoliciesNotFoundError) {
  // Create an empty file
  std::string test_file = absl::StrCat(testing::TempDir(), "policy_file");
  std::ofstream policy_file(test_file);
  ASSERT_TRUE(policy_file.is_open());
  policy_file.close();
  absl::SetFlag(&FLAGS_appraisal_policy_file, test_file);
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPolicies(/*n=*/1),
                             absl::StatusCode::kNotFound, "No policies found");
}

TEST(PolicyFetcherLocal, CreateError) {
  absl::SetFlag(&FLAGS_appraisal_policy_file, "nonexistent");
  HATS_EXPECT_STATUS_MESSAGE(PolicyFetcher::Create(),
                             absl::StatusCode::kFailedPrecondition,
                             "Failed to open: nonexistent");
}

TEST(PolicyFetcherLocal, GetLatestNPoliciesForDigestSuccessfull) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string policy_file, WriteTestPolicyToFile());
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());
  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());

  std::string first_application_digest;
  ASSERT_TRUE(absl::HexStringToBytes(
      expected_policies.policies(0).measurement().container_binary_sha256(0),
      &first_application_digest));
  HATS_EXPECT_OK_AND_HOLDS(
      policy_fetcher->GetLatestNPoliciesForDigest(first_application_digest,
                                                  /*n=*/5),
      EqualsProto(kTestAppraisalPolicies));

  std::string second_application_digest;
  ASSERT_TRUE(absl::HexStringToBytes(
      expected_policies.policies(0).measurement().container_binary_sha256(1),
      &second_application_digest));
  HATS_EXPECT_OK_AND_HOLDS(
      policy_fetcher->GetLatestNPoliciesForDigest(second_application_digest,
                                                  /*n=*/5),
      EqualsProto(kTestAppraisalPolicies));
}

TEST(PolicyFetcherLocal, GetLatestNPoliciesForDigestNotFoundError) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string policy_file, WriteTestPolicyToFile());
  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_policies,
                            GetTestAppraisalPolicies());
  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPoliciesForDigest(
                                 /*application_digest*/ "some_digest",
                                 /*n=*/5),
                             absl::StatusCode::kNotFound, "No policies found");
}

// Test that GetLatestNPolicies returns the expected result when blobs are
// provided.
TEST(PolicyFetcherLocal, GetLatestNPoliciesSuccess_WithBlobs) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string policy_file, WriteTestPolicyToFile());
  HATS_ASSERT_OK_AND_ASSIGN(TestBlobInfo blob_info, CreateTestBlobDirectory());

  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  absl::SetFlag(&FLAGS_stage0_blob_directory, blob_info.directory_path);

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_result,
                            GetTestAppraisalPolicies());
  (*expected_result
        .mutable_stage0_binary_sha256_to_blob())[blob_info.blob_sha256_digest] =
      blob_info.blob_data;

  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  std::string expected_text_proto;
  google::protobuf::TextFormat::PrintToString(expected_result,
                                              &expected_text_proto);
  HATS_EXPECT_OK_AND_HOLDS(policy_fetcher->GetLatestNPolicies(/*n=*/1),
                           EqualsProto(expected_text_proto));
}

// Test that GetLatestNPolicies returns NotFoundError when the policy file is
// empty, even when blobs are provided.
TEST(PolicyFetcherLocal, GetLatestNPoliciesNotFoundError_WithBlobs) {
  // Create an empty file
  std::string test_file = absl::StrCat(testing::TempDir(), "policy_file");
  std::ofstream policy_file(test_file);
  ASSERT_TRUE(policy_file.is_open());
  policy_file.close();

  // Create a valid blob directory and file
  HATS_ASSERT_OK_AND_ASSIGN(TestBlobInfo blob_info, CreateTestBlobDirectory());

  absl::SetFlag(&FLAGS_appraisal_policy_file, test_file);
  absl::SetFlag(&FLAGS_stage0_blob_directory, blob_info.directory_path);

  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPolicies(/*n=*/1),
                             absl::StatusCode::kNotFound, "No policies found");
}

// Test that GetLatestNPoliciesForDigest returns the expected result when the
// application digest is found in the policy file and blobs are provided.
TEST(PolicyFetcherLocal, GetLatestNPoliciesForDigestSuccess_WithBlobs) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string policy_file, WriteTestPolicyToFile());
  HATS_ASSERT_OK_AND_ASSIGN(TestBlobInfo blob_info, CreateTestBlobDirectory());

  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  absl::SetFlag(&FLAGS_stage0_blob_directory, blob_info.directory_path);

  HATS_ASSERT_OK_AND_ASSIGN(AppraisalPolicies expected_result,
                            GetTestAppraisalPolicies());
  (*expected_result
        .mutable_stage0_binary_sha256_to_blob())[blob_info.blob_sha256_digest] =
      blob_info.blob_data;

  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());

  std::string expected_text_proto;
  google::protobuf::TextFormat::PrintToString(expected_result,
                                              &expected_text_proto);

  std::string first_application_digest;
  ASSERT_TRUE(absl::HexStringToBytes(
      expected_result.policies(0).measurement().container_binary_sha256(0),
      &first_application_digest));

  HATS_EXPECT_OK_AND_HOLDS(
      policy_fetcher->GetLatestNPoliciesForDigest(first_application_digest,
                                                  /*n=*/5),
      EqualsProto(expected_text_proto));

  std::string second_application_digest;
  ASSERT_TRUE(absl::HexStringToBytes(
      expected_result.policies(0).measurement().container_binary_sha256(1),
      &second_application_digest));
  HATS_EXPECT_OK_AND_HOLDS(
      policy_fetcher->GetLatestNPoliciesForDigest(second_application_digest,
                                                  /*n=*/5),
      EqualsProto(expected_text_proto));
}

// Test that GetLatestNPoliciesForDigest returns NotFoundError when the
// application digest is not found in the policy file, even when blobs are
// provided.
TEST(PolicyFetcherLocal, GetLatestNPoliciesForDigestNotFoundError_WithBlobs) {
  HATS_ASSERT_OK_AND_ASSIGN(std::string policy_file, WriteTestPolicyToFile());
  HATS_ASSERT_OK_AND_ASSIGN(TestBlobInfo blob_info, CreateTestBlobDirectory());

  absl::SetFlag(&FLAGS_appraisal_policy_file, policy_file);
  absl::SetFlag(&FLAGS_stage0_blob_directory, blob_info.directory_path);

  HATS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PolicyFetcher> policy_fetcher,
                            PolicyFetcher::Create());
  HATS_EXPECT_STATUS_MESSAGE(policy_fetcher->GetLatestNPoliciesForDigest(
                                 /*application_digest*/ "some_digest",
                                 /*n=*/5),
                             absl::StatusCode::kNotFound, "No policies found");
}

}  // namespace
}  // namespace pcit::tvs
