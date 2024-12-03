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

load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "launcher",
    srcs = ["launcher.rs"],
    deps = [
        "//tvs/trusted_tvs/proto:tvs_enclave",
        "@cxx.rs//:cxx",
        "@oak//micro_rpc",
        "@oak//oak_launcher_utils",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:tokio",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "launcher.rs",
    deps = [
        ":launcher",
    ],
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
        "//status_macro:status_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        # "//tvs/trusted_tvs:trusted-tvs-bridge",
        "//key_manager:key-fetcher-interface",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        ":bridge",
    ],
)
