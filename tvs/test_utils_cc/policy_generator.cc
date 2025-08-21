// Copyright 2025 Google LLC.
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

#include "tvs/test_utils_cc/policy_generator.h"

#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "openssl/sha.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace pcit::tvs::test_utils_cc {

using bazel::tools::cpp::runfiles::Runfiles;

// Helper to read the binary file
absl::StatusOr<std::string> GetStage0Blob() {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest(&error));
  if (runfiles == nullptr) {
    return absl::InternalError(
        absl::StrCat("Failed to create Runfiles: ", error));
  }

  std::string path = runfiles->Rlocation("tvs/test_data/stage0_bin_for_test");
  std::ifstream file_stream(path, std::ios::binary);
  if (!file_stream) {
    return absl::NotFoundError(absl::StrCat("Could not open file: ", path));
  }
  std::stringstream buffer;
  buffer << file_stream.rdbuf();
  return buffer.str();
}

absl::StatusOr<AppraisalPolicies> CreateDynamicGenoaPolicy() {
  // Get Stage0 binary and hash it
  absl::StatusOr<std::string> stage0_blob_status = GetStage0Blob();
  if (!stage0_blob_status.ok()) {
    return stage0_blob_status.status();
  }
  std::string stage0_blob = *stage0_blob_status;

  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const uint8_t*>(stage0_blob.data()),
         stage0_blob.size(), hash.data());
  std::string stage0_hash_hex = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(hash.data()), hash.size()));

  // Build the AppraisalPolicies proto in C++
  AppraisalPolicies policies;
  AppraisalPolicy& policy = *policies.add_policies();
  policy.set_description("Test against golden dynamic evidence genoa");

  Measurement& measurement = *policy.mutable_measurement();
  Stage0Measurement& stage0_measurement =
      *measurement.mutable_stage0_measurement();
  AmdSevDynamic& amd_sev_dynamic =
      *stage0_measurement.mutable_amd_sev_dynamic();

  amd_sev_dynamic.add_stage0_ovmf_binary_hash(stage0_hash_hex);

  oak::attestation::v1::TcbVersion& tcb =
      *amd_sev_dynamic.mutable_min_tcb_version();
  tcb.set_boot_loader(10);
  tcb.set_microcode(84);
  tcb.set_snp(25);

  CpuInfo& cpu_info = *amd_sev_dynamic.add_cpu_info();
  cpu_info.set_family(25);
  cpu_info.set_model(17);
  cpu_info.set_stepping(1);

  amd_sev_dynamic.add_vcpu_count(4);

  measurement.set_kernel_image_sha256(
      "f9d0584247b46cc234a862aa8cd08765b38405022253a78b9af189c4cedbe447");
  measurement.set_kernel_setup_data_sha256(
      "75f091da89ce81e9decb378c3b72a948aed5892612256b3a6e8305ed034ec39a");
  measurement.set_init_ram_fs_sha256(
      "b2b5eda097c2e15988fd3837145432e3792124dbe0586edd961efda497274391");
  measurement.set_memory_map_sha256(
      "11103720aab9f4eff4b68b7573b6968e3947e5d7552ace7cebacdbdb448b68fe");
  measurement.set_acpi_table_sha256(
      "194afdde1699c335fdd4ed99fd36d9500230fbda0ab14f6d95fc35d219ddf32e");
  measurement.set_kernel_cmd_line_regex(
      "^ console=ttyS0 panic=-1 brd.rd_nr=1 brd.rd_size=10485760 "
      "brd.max_part=1 "
      "ip=10.0.2.15:::255.255.255.0::enp0s1:off quiet -- "
      "--launcher-addr=vsock://2:.*$");
  measurement.set_system_image_sha256(
      "3c59bd10c2b890ff152cc57fdca0633693acbb04982da90c670de6530fa8a836");
  measurement.add_container_binary_sha256(
      "b0803886a6e096bf1c9eacaa77dd1514134d2e88a7734af9ba2dbf650884f899");

  Signature& signature = *policy.add_signature();
  signature.set_signature(
      "972449509fe27fa8fffbebe77b83ed908e698b6efa09727c38fbd84186db79b24a79f5a4"
      "0d"
      "dbda77b3db066293c4931f8b036d0f2193326f2b7b8dd3de80509f");

  (*policies.mutable_stage0_binary_sha256_to_blob())[stage0_hash_hex] =
      stage0_blob;

  return policies;
}

}  // namespace pcit::tvs::test_utils_cc
