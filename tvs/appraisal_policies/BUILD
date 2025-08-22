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

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "policy-fetcher-interface",
    hdrs = ["policy-fetcher.h"],
    deps = [
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "policy-fetcher-local",
    srcs = ["policy-fetcher-local.cc"],
    deps = [
        ":policy-fetcher-interface",
        "//status_macro:status_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/container:flat_hash_map",
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
        "@boringssl//:crypto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "policy-fetcher-gcp",
    srcs = ["policy-fetcher-gcp.cc"],
    hdrs = [
        "policy-fetcher-gcp.h",
    ],
    defines = select({
        "//:dynamic_attestation_enabled": ["DYNAMIC_ATTESTATION"],
        "//conditions:default": [],
    }),
    deps = [
        ":policy-fetcher-interface",
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
    defines = select({
        "//:dynamic_attestation_enabled": ["DYNAMIC_ATTESTATION"],
        "//conditions:default": [],
    }),
    deps = [
        ":policy-fetcher-gcp",
        "//status_macro:status_test_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)
