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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "tvs-server_main",
    srcs = ["tvs-server_main.cc"],
    deps = [
        ":tvs-service",
        "//status_macro:status_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ] + select({
        "//:gcp": [
            "//key_manager:key-fetcher-gcp",
            "//tvs/appraisal_policies:policy-fetcher-gcp",
        ],
        "//conditions:default": [
            "//key_manager:key-fetcher-local",
            "//tvs/appraisal_policies:policy-fetcher-local",
        ],
    }),
)

cc_library(
    name = "tvs-service",
    srcs = ["tvs-service.cc"],
    hdrs = ["tvs-service.h"],
    deps = [
        "//key_manager:key-fetcher-interface",
        "//tvs/appraisal_policies:policy-fetcher-interface",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/trusted_tvs/library:trusted-tvs-bridge",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "tvs-service_test",
    size = "small",
    srcs = ["tvs-service_test.cc"],
    data = [
        "//tvs/test_data:tvs_test_data",
    ],
    deps = [
        ":tvs-service",
        "//crypto:test-ec-key",
        "//key_manager:test-key-fetcher",
        "//status_macro:status_macros",
        "//status_macro:status_test_macros",
        "//tvs/appraisal_policies:policy-fetcher-local",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/test_client:tvs-untrusted-client",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf_headers",
    ],
)
