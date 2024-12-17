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
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_library")

cc_library(
    name = "policy-fetcher-wrapper",
    srcs = ["policy-fetcher-wrapper.cc"],
    hdrs = ["policy-fetcher-wrapper.h"],
    visibility = ["//visibility:private"],
    deps = [
        ":policy-fetcher-wrapper-bridge/include",
        "//tvs/appraisal_policies:policy-fetcher-interface",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/status:statusor",
        "@cxx.rs//:cxx",
    ],
)

rust_library(
    name = "dynamic-policy-manager",
    srcs = glob(["src/**"]),
    visibility = [
        "//tvs/trusted_tvs:__subpackages__",
    ],
    deps = [
        ":policy-fetcher-wrapper",
        ":policy-fetcher-wrapper-bridge",
        "//tvs/appraisal_policies/policy_manager:policy-manager",
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@cxx.rs//:cxx",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
    ],
)

rust_cxx_bridge(
    name = "policy-fetcher-wrapper-bridge",
    src = "src/lib.rs",
    deps = [
        ":policy-fetcher-wrapper",
    ],
)
