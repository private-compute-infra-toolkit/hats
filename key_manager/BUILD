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
load("@rules_rust//rust:defs.bzl", "rust_binary")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "kms-client-interface",
    hdrs = [
        "kms-client.h",
    ],
    deps = [
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
    ],
)

cc_library(
    name = "gcp-kms-client",
    srcs = ["gcp-kms-client.cc"],
    hdrs = [
        "gcp-kms-client.h",
    ],
    deps = [
        ":kms-client-interface",
        "//status_macro:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
        "@google_cloud_cpp//:kms",
    ],
)

cc_test(
    name = "gcp-kms-client_test",
    size = "small",
    srcs = ["gcp-kms-client_test.cc"],
    deps = [
        ":gcp-kms-client",
        "//status_macro:status_test_macros",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:kms",
        "@google_cloud_cpp//:kms_mocks",
    ],
)

rust_binary(
    name = "key-gen",
    srcs = ["key-gen.rs"],
    deps = [
        "//crypto:secret-sharing-noffi",
        "@enclave//crypto",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:hpke",
        "@hats_crate_index//:rand",
        "@hats_crate_index//:serde_json",
        "@oak_crates_index//:clap",
    ],
)

cc_library(
    name = "public-key-fetcher",
    hdrs = [
        "public-key-fetcher.h",
    ],
    deps = [
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "public-key-fetcher-gcp",
    srcs = ["public-key-fetcher-gcp.cc"],
    hdrs = [
        "public-key-fetcher.h",
        "public-key-fetcher-gcp.h",
    ],
    deps = [
        "//gcp_common:flags",
        "//status_macro:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:spanner",
    ],
)

cc_test(
    name = "public-key-fetcher-gcp_test",
    size = "small",
    srcs = ["public-key-fetcher-gcp_test.cc"],
    deps = [
        ":public-key-fetcher-gcp",
        "//status_macro:status_test_macros",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:common",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)

cc_library(
    name = "key-fetcher-interface",
    hdrs = ["key-fetcher.h"],
    deps = [
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "key-fetcher-local",
    srcs = ["key-fetcher-local.cc"],
    deps = [
        ":key-fetcher-interface",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "key-fetcher-local_test",
    size = "small",
    srcs = [":key-fetcher-local_test.cc"],
    deps = [
        ":key-fetcher-interface",
        ":key-fetcher-local",
        "//status_macro:status_test_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "key-fetcher-gcp",
    srcs = ["key-fetcher-gcp.cc"],
    hdrs = [
        "key-fetcher-gcp.h",
    ],
    deps = [
        ":key-fetcher-interface",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//gcp_common:flags",
        "//key_manager:gcp-kms-client",
        "//status_macro:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:kms",
        "@google_cloud_cpp//:spanner",
    ],
)

cc_test(
    name = "key-fetcher-gcp_test",
    size = "small",
    srcs = [":key-fetcher-gcp_test.cc"],
    deps = [
        ":key-fetcher-gcp",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//status_macro:status_test_macros",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:kms",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)

cc_library(
    name = "test-key-fetcher",
    srcs = ["test-key-fetcher.cc"],
    hdrs = ["test-key-fetcher.h"],
    deps = [
        ":key-fetcher-interface",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)
