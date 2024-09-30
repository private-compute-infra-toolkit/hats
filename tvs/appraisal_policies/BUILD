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
load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "policy-fetcher-local",
    srcs = ["policy-fetcher-local.cc"],
    hdrs = ["policy-fetcher.h"],
    deps = [
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
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
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
        "//gcp_common:gcp-status",
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
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/status:status_matchers",
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
        ":build",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//oak_proto_rust",
    ],
)

rust_test(
    name = "policy-signature_test",
    size = "small",
    srcs = ["policy-signature.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//oak_proto_rust",
    ],
)

cargo_build_script(
    name = "build",
    srcs = [
        "build.rs",
    ],
    build_script_env = {
        "OAK_PROTO_INCLUDE": "$(location @oak//proto/attestation:evidence.proto)",
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
    },
    data = [
        "//tvs/proto:appraisal_policies_proto",
        "@com_google_protobuf//:protoc",
        "@oak//proto:digest.proto",
        "@oak//proto/attestation:evidence.proto",
        "@oak//proto/attestation:reference_value.proto",
        "@oak//proto/attestation:tcb_version.proto",
    ],
    deps = [
        "@oak_crates_index//:prost-build",
    ],
)
