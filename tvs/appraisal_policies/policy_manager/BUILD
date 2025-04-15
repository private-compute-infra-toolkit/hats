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
    crate_features = ["regex"],
    deps = [
        "//tvs/appraisal_policies/policy_signature:policy-signature",
        "//tvs/proto_rust:tvs-proto",
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@hats_crate_index//:hex",
        "@oak//oak_attestation_verification:oak_attestation_verification_with_regex",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:log",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:regex",
    ],
)

rust_test(
    name = "policy-manager_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = ":policy-manager",
    crate_features = ["regex"],
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
