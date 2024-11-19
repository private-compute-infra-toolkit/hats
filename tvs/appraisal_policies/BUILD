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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "policy-fetcher-local",
    srcs = ["policy-fetcher-local.cc"],
    hdrs = ["policy-fetcher.h"],
    deps = [
        "//status_macro:status_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
    ],
)

cc_test(
    name = "policy-fetcher-local_test",
    size = "small",
    srcs = [":policy-fetcher-local_test.cc"],
    deps = [
        ":policy-fetcher-local",
        "//status_macro:status_test_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "policy-fetcher-gcp",
    srcs = ["policy-fetcher-gcp.cc"],
    hdrs = [
        "policy-fetcher.h",
        "policy-fetcher-gcp.h",
    ],
    deps = [
        "//gcp_common:flags",
        "//status_macro:status_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:spanner",
    ],
)

cc_test(
    name = "policy-fetcher-gcp_test",
    size = "small",
    srcs = [":policy-fetcher-gcp_test.cc"],
    deps = [
        ":policy-fetcher-gcp",
        "//status_macro:status_test_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)

rust_library(
    name = "policy-signature",
    srcs = ["policy-signature.rs"],
    crate_name = "policy_signature",
    deps = [
        "//tvs/proto_rust:tvs-proto",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
    ],
)

rust_test(
    name = "policy-signature_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = "policy-signature",
)

rust_library(
    name = "policy-manager",
    srcs = ["policy-manager.rs"],
    crate_features = ["regex"],
    deps = [
        "//tvs/appraisal_policies:policy-signature",
        "//tvs/proto_rust:tvs-proto",
        "@hats_crate_index//:hex",
        "@oak//oak_attestation_verification:oak_attestation_verification_with_regex",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
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
    name = "policy-manager-noregex",
    srcs = ["policy-manager.rs"],
    crate_name = "policy_manager",
    deps = [
        "//tvs/appraisal_policies:policy-signature",
        "//tvs/proto_rust:tvs-proto",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
    ],
)
