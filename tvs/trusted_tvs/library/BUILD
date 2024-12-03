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
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "trusted-tvs",
    srcs = glob(["src/**"]),
    crate_features = ["default"],
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
        "//tvs/key_fetcher_wrapper:key-fetcher",
        "@cxx.rs//:cxx",
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@oak_crates_index//:anyhow",
    ],
)

rust_test(
    name = "trusted-tvs_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = ":trusted-tvs",
    crate_features = ["default"],
    deps = [
        "//tvs/client:trusted-client-noffi",
        "@hats_crate_index//:hex",
    ],
)

rust_cxx_bridge(
    name = "trusted-tvs-bridge",
    src = "src/interface.rs",
    deps = [
        ":trusted-tvs",
    ],
)

rust_library(
    name = "trusted-tvs-enclave",
    srcs = glob(["src/**"]),
    crate_features = [
        "enclave",
        "no_std",
    ],
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
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@oak_crates_index//:anyhow",
        "@oak//micro_rpc",
        "//tvs/trusted_tvs/proto:tvs_enclave",
    ],
)
