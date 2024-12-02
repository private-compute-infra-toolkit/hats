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
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "trusted-tvs",
    srcs = [
        "request_handler.rs",
        "service.rs",
        "trusted_tvs.rs",
    ],
    crate_root = "trusted_tvs.rs",
    deps = [
        "//tvs/proto_rust:tvs-proto",
        "//tvs/appraisal_policies:policy-manager",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//oak_proto_rust",
        "@oak//oak_attestation_verification",
        "@enclave//crypto",
        "@enclave//handshake",
        ":key-fetcher",
        "@cxx.rs//:cxx",
        ":key-provider",
        "@oak_crates_index//:anyhow",
    ],
)

rust_test(
    name = "trusted-tvs_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = ":trusted-tvs",
    deps = [
        "@hats_crate_index//:hex",
        "@oak_crates_index//:anyhow",
    ],
)

rust_cxx_bridge(
    name = "trusted-tvs-bridge",
    src = "trusted_tvs.rs",
    deps = [
        ":trusted-tvs",
    ],
)

cc_library(
    name = "key-fetcher-wrapper",
    srcs = ["key-fetcher-wrapper.cc"],
    hdrs = ["key-fetcher-wrapper.h"],
    visibility = ["//visibility:private"],
    deps = [
        ":key-fetcher-wrapper-bridge/include",
        "//key_manager:key-fetcher-interface",
        "//key_manager:test-key-fetcher",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@cxx.rs//:cxx",
    ],
)

rust_library(
    name = "key-fetcher",
    srcs = ["key-fetcher.rs"],
    crate_name = "key_fetcher",
    visibility = [
        "//client/orchestrator:__pkg__",
        "//tvs/client:__pkg__",
    ],
    deps = [
        ":key-fetcher-wrapper",
        ":key-fetcher-wrapper-bridge",
        ":key-provider",
        "@cxx.rs//:cxx",
        "@oak_crates_index//:anyhow",
    ],
)

rust_cxx_bridge(
    name = "key-fetcher-wrapper-bridge",
    src = "key-fetcher.rs",
    deps = [
        ":key-fetcher-wrapper",
    ],
)

rust_library(
    name = "key-provider",
    srcs = ["key-provider.rs"],
    deps = [
        "@oak_crates_index//:anyhow",
    ],
)

rust_library(
    name = "trusted-tvs-enclave",
    srcs = [
        "request_handler.rs",
        "service.rs",
        "trusted_tvs.rs",
    ],
    crate_features = ["noffi"],
    crate_name = "trusted_tvs",
    crate_root = "trusted_tvs.rs",
    deps = [
        "//tvs/proto_rust:tvs-proto",
        "//tvs/appraisal_policies:policy-manager-noregex",
        "@oak_crates_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//oak_proto_rust",
        "@oak//oak_attestation_verification",
        "@enclave//crypto:crypto_nostd",
        "@enclave//handshake:handshake_nostd",
        ":key-provider",
        "@oak_crates_index//:anyhow",
    ],
)

rust_library(
    name = "enclave_service",
    srcs = ["enclave_service.rs"],
    deps = [
        "//tvs/trusted_tvs:trusted-tvs-enclave",
        "//tvs/trusted_tvs/enclave/proto:tvs_enclave",
        "@oak//micro_rpc",
        "@oak_crates_index//:log",
    ],
)
