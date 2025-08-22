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
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "absl/cleanup/cleanup.h"
#include "absl/container/flat_hash_map.h"
#include "absl/flags/flag.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "status_macro/status_macros.h"
#include "tvs/appraisal_policies/policy-fetcher.h"
#include "tvs/proto/appraisal_policies.pb.h"

ABSL_FLAG(std::string, appraisal_policy_file, "",
          "Policy that defines acceptable evidence.");
ABSL_FLAG(std::string, stage0_blob_directory, "",
          "Path to the directory containing stage0 blobs. The filename of each "
          "blob must be its hex-encoded sha256 digest.");

namespace pcit::tvs {

namespace {

absl::StatusOr<AppraisalPolicies> ReadAppraisalPolicies(
    absl::string_view filename) {
  std::ifstream if_stream({std::string(filename)});
  if (!if_stream.is_open()) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to open: ", filename));
  }
  google::protobuf::io::IstreamInputStream istream(&if_stream);
  AppraisalPolicies appraisal_policies;
  if (!google::protobuf::TextFormat::Parse(&istream, &appraisal_policies)) {
    return absl::FailedPreconditionError(
        absl::StrCat("Failed to parse: ", filename));
  }
  return appraisal_policies;
}

// Load stage0 blobs from a directory. The directory must contain files with
// hex-encoded sha256 digest as their filename.
absl::StatusOr<absl::flat_hash_map<std::string, std::string>> LoadStage0Blobs(
    absl::string_view directory_path) {
  absl::flat_hash_map<std::string, std::string> blobs;
  if (directory_path.empty()) {
    return blobs;
  }

  // Use the POSIX API to open and read the directory
  DIR* dirp = opendir(std::string(directory_path).c_str());
  if (dirp == nullptr) {
    return absl::InternalError(
        absl::StrCat("Failed to open blob directory: ", directory_path));
  }
  // Ensure the directory handle is closed when we're done.
  absl::Cleanup closer = [dirp] { closedir(dirp); };

  struct dirent* dp;
  errno = 0;
  while ((dp = readdir(dirp)) != nullptr) {
    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
      continue;
    }

    std::string filename = dp->d_name;
    std::string full_path = absl::StrCat(directory_path, "/", filename);

    // use stat to ensure regular file
    struct stat statbuf;
    if (stat(full_path.c_str(), &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
      continue;
    }
    // Read binary content of the file
    std::ifstream file_stream(full_path, std::ios::binary);
    if (!file_stream) {
      return absl::InternalError(
          absl::StrCat("Failed to open blob file: ", full_path));
    }
    std::string content((std::istreambuf_iterator<char>(file_stream)),
                        std::istreambuf_iterator<char>());

    blobs[filename] = std::move(content);
  }
  if (errno != 0) {
    return absl::InternalError(
        absl::StrCat("Error reading directory: ", directory_path));
  }
  return blobs;
}

// Index appriasal policies by their application digest(s)
absl::StatusOr<std::unordered_map<std::string, AppraisalPolicies>>
IndexAppraisalPolicies(const AppraisalPolicies& appraisal_policies) {
  std::unordered_map<std::string, AppraisalPolicies> indexed_appraisal_policies;

  // The policies are passed by const reference to avoid a copy.
  for (const AppraisalPolicy& appraisal_policy :
       appraisal_policies.policies()) {
    // If an appraisal policy has an empty list of container binaries, ignore
    // this invalid policy, skip and continue to the next
    if (appraisal_policy.measurement().container_binary_sha256().empty()) {
      continue;
    }

    // Iterate through each container binary application digest in this policy
    // and insert into the unordered map
    for (const std::string& digest_hex :
         appraisal_policy.measurement().container_binary_sha256()) {
      std::string application_digest;
      if (!absl::HexStringToBytes(digest_hex, &application_digest)) {
        return absl::InvalidArgumentError(
            "Failed to parse application digest. The digest should be "
            "formatted as a hex string.");
      }

      // operator[] inserts a key with a default-constructed AppraisalPolicies
      // if it's not already there; otherwise, it returns a reference to the
      // existing one. We then add a copy of the current policy to the list of
      // policies for that digest.
      AppraisalPolicies& policies_for_digest =
          indexed_appraisal_policies[application_digest];
      *policies_for_digest.add_policies() = appraisal_policy;
    }
  }
  return indexed_appraisal_policies;
}

// Dynamic attestation note:
// This local implementation of the PolicyFetcher is a simple simulator for
// local development and testing. It loads all policies and all blobs from the
// filesystem at startup. When a Get... method is called, it returns the
// requested subset of policies along with the *entire* map of all known blobs.
// This differs slightly from the production GCP fetcher, which only returns
// blobs that are explicitly linked to the returned policies. This simpler
// approach is sufficient for local testing, as the downstream PolicyManager
// will receive all the blobs it needs (and some harmless extra ones).
class PolicyFetcherLocal final : public PolicyFetcher {
 public:
  PolicyFetcherLocal() = delete;
  PolicyFetcherLocal(
      std::unordered_map<std::string, AppraisalPolicies> policies,
      absl::flat_hash_map<std::string, std::string> all_stage0_blobs)
      : policies_(std::move(policies)),
        all_stage0_blobs_(std::move(all_stage0_blobs)) {}

  // Arbitrary return `n` policies as we don't have update timestamp
  // in the file.
  absl::StatusOr<AppraisalPolicies> GetLatestNPolicies(int n) override {
    // Number of policies found;
    int counter = 0;
    AppraisalPolicies result;
    for (const auto& [_, policies] : policies_) {
      for (const AppraisalPolicy& policy : policies.policies()) {
        *result.add_policies() = policy;
        if (++counter == n) break;
      }
      if (counter == n) break;
    }

    if (result.policies().size() == 0) {
      return absl::NotFoundError("No policies found");
    }

    // Add stage0 blobs to the result.
    for (const auto& [digest, blob] : all_stage0_blobs_) {
      (*result.mutable_stage0_binary_sha256_to_blob())[digest] = blob;
    }
    return result;
  }

  // Arbitrary return `n` policies as we don't have update timestamp
  // in the file.
  absl::StatusOr<AppraisalPolicies> GetLatestNPoliciesForDigest(
      absl::string_view application_digest, int n) override {
    // Number of policies found;
    AppraisalPolicies result;
    if (auto it = policies_.find(std::string(application_digest));
        it != policies_.end()) {
      int counter = 0;
      for (const AppraisalPolicy& policy : it->second.policies()) {
        *result.add_policies() = policy;
        if (++counter == n) break;
      }
    }

    if (result.policies().size() == 0) {
      return absl::NotFoundError("No policies found");
    }
    // Add the blobs to the final result object
    for (const auto& [digest, blob] : all_stage0_blobs_) {
      (*result.mutable_stage0_binary_sha256_to_blob())[digest] = blob;
    }
    return result;
  }

 private:
  // Policies keyed by application digest i.e. container_binary_sha256 filed.
  // The key is the byte representation of the digest.
  const std::unordered_map<std::string, AppraisalPolicies> policies_;
  const absl::flat_hash_map<std::string, std::string> all_stage0_blobs_;
};

}  // namespace

// Command-line use, take in flags for appraisal policy and stage0
// blob directory (optional)
absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create() {
  const std::string appraisal_policy_file =
      absl::GetFlag(FLAGS_appraisal_policy_file);
  const std::string stage0_blob_directory =
      absl::GetFlag(FLAGS_stage0_blob_directory);

  if (stage0_blob_directory.empty()) {
    return Create(appraisal_policy_file);
  } else {
    return CreateWithBlobs(appraisal_policy_file, stage0_blob_directory);
  }
}

// Programmatic use  for appraisal policy only
absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::Create(
    const std::string& file_path) {
  HATS_ASSIGN_OR_RETURN(AppraisalPolicies policies,
                        ReadAppraisalPolicies(file_path));
  std::unordered_map<std::string, AppraisalPolicies> indexed_appraisal_policies;
  HATS_ASSIGN_OR_RETURN(indexed_appraisal_policies,
                        IndexAppraisalPolicies(policies));
  return std::make_unique<PolicyFetcherLocal>(
      std::move(indexed_appraisal_policies),
      absl::flat_hash_map<std::string, std::string>());  // empty map for blobs
}

// Programmatic use for appraisal policy and blobs
absl::StatusOr<std::unique_ptr<PolicyFetcher>> PolicyFetcher::CreateWithBlobs(
    const std::string& file_path,
    const std::string& stage0_blob_directory_path) {
  HATS_ASSIGN_OR_RETURN(AppraisalPolicies policies,
                        ReadAppraisalPolicies(file_path));
  std::unordered_map<std::string, AppraisalPolicies> indexed_appraisal_policies;
  HATS_ASSIGN_OR_RETURN(indexed_appraisal_policies,
                        IndexAppraisalPolicies(policies));
  // load blobs from the (optional) provided directory path
  absl::flat_hash_map<std::string, std::string> all_stage0_blobs;
  HATS_ASSIGN_OR_RETURN(all_stage0_blobs,
                        LoadStage0Blobs(stage0_blob_directory_path));
  return std::make_unique<PolicyFetcherLocal>(
      std::move(indexed_appraisal_policies), std::move(all_stage0_blobs));
}

}  // namespace pcit::tvs
