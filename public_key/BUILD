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
    name = "public-key-server_main",
    srcs = ["public-key-server_main.cc"],
    deps = [
        ":public-key-server",
        "//key_manager:public-key-fetcher-gcp",
        "//status_macro:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "public-key-server",
    srcs = ["public-key-server.cc"],
    hdrs = ["public-key-server.h"],
    deps = [
        "//key_manager:public-key-fetcher",
        "//public_key/proto:public_key_service_cc_grpc",
        "//public_key/proto:public_key_service_cc_proto",
        "//status_macro:status_macros",
        "//status_macro:status_util",
        "@com_github_grpc_grpc//:grpc++_reflection",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:empty_cc_proto",
        "@curl",
        "@google_cloud_cpp//:storage",
    ],
)

cc_test(
    name = "public-key-server_test",
    size = "small",
    srcs = ["public-key-server_test.cc"],
    deps = [
        ":public-key-server",
        "//key_manager:public-key-fetcher",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@cpp-httplib//:cpp-httplib",
        "@google_cloud_cpp//:storage_mocks",
        "@google_cloud_cpp//google/cloud/storage:storage_client_testing",
    ],
)
