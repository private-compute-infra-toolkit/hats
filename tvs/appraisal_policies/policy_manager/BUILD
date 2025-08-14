# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "policy-manager",
    srcs = glob(["src/**"]),
    crate_features = ["regex"] + select({
        "//:dynamic_attestation_enabled": ["dynamic_attestation"],
        "//conditions:default": [],
    }),
    deps = [
        "//tvs/appraisal_policies/policy_signature:policy-signature",
        "//tvs/proto_rust:tvs-proto",
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@oak//oak_attestation_verification:oak_attestation_verification_with_regex",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:log",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:regex",
    ] + select({
        # Dependencies ONLY for dynamic attestation.
        "//:dynamic_attestation_enabled": [
            "@oak//oak_sev_snp_attestation_report",
            "@oak_crates_index//:hashbrown",
            "@oak_crates_index//:zerocopy",
            "@sev-snp-utils//:common",
            "@sev-snp-utils//:error",
            "@sev-snp-utils//:measure",
            "@sev-snp-utils//:vcpu_types",
        ],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "policy-manager_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = ":policy-manager",
    crate_features = ["regex"] + select({
        "//:dynamic_attestation_enabled": ["dynamic_attestation"],
        "//conditions:default": [],
    }),
    data = [
        "//google_internal/oak_artifacts:stage0_bin_file",
    ],
    deps = select({
        "//:dynamic_attestation_enabled": [
            "@oak//oak_sev_snp_attestation_report",
            "@oak_crates_index//:env_logger",
            "@oak_crates_index//:hashbrown",
            "@oak_crates_index//:hex",
            "@oak_crates_index//:sha2",
            "@oak_crates_index//:zerocopy",
            "@rules_rust//tools/runfiles",
            "@sev-snp-utils//:common",
            "@sev-snp-utils//:error",
            "@sev-snp-utils//:measure",
            "@sev-snp-utils//:vcpu_types",
        ],
        "//conditions:default": [],
    }),
)

rust_library(
    name = "policy-manager-no-std",
    srcs = glob(["src/**"]),
    crate_name = "policy_manager",
    deps = [
        "//tvs/appraisal_policies/policy_signature:policy-signature",
        "//tvs/proto_rust:tvs-proto",
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
    ],
)
