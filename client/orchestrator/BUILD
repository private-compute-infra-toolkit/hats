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

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_binary(
    name = "orchestrator_main",
    srcs = ["orchestrator_main.rs"],
    deps = [
        ":hats-server",
        ":tvs-grpc-client",
        ":tvs-secret-manager",
        "//crypto/secret_sharing:secret-sharing-noffi",
        "@hats_crate_index//:hex",
        "@oak//oak_attestation",
        "@oak//oak_attestation_types",
        "@oak//oak_containers/attestation:oak_containers_attestation",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-util",
    ],
)

rust_test(
    name = "orchestrator_main_test",
    size = "small",
    crate = ":orchestrator_main",
    deps = [
        "//client/proto_rust:client-proto",
        "@oak_crates_index//:mockall",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tonic",
    ],
)

rust_library(
    name = "tvs-grpc-client",
    srcs = ["tvs-grpc-client.rs"],
    crate_features = select({
        "//:dynamic_attestation_enabled": ["dynamic_attestation"],
        "//conditions:default": [],
    }),
    deps = [
        "//client/proto_rust:client-proto",
        "//tvs/client:trusted-client-noffi",
        "//tvs/proto_rust:tvs-proto",
        "@hats_crate_index//:hex",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:async-stream",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:hyper-util",
        "@oak_crates_index//:mockall",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tokio-vsock",
        "@oak_crates_index//:tonic",
        "@oak_crates_index//:tower",
    ],
)

rust_test(
    name = "tvs-grpc-client_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = ":tvs-grpc-client",
    crate_features = select({
        "//:dynamic_attestation_enabled": ["dynamic_attestation"],
        "//conditions:default": [],
    }),
    deps = [
        "//tvs/key_fetcher_wrapper:key-fetcher",
        "//tvs/trusted_tvs/library:trusted-tvs",
        "@enclave//crypto",
        "@oak_crates_index//:futures",
        "@oak_crates_index//:tokio-stream",
    ] + select({
        "//:dynamic_attestation_enabled": [
            "//tvs/test_utils_rs",
        ],
        "//conditions:default": [],
    }),
)

rust_library(
    name = "hats-server",
    srcs = ["hats-server.rs"],
    deps = [
        ":tvs-grpc-client",
        ":tvs-secret-manager",
        "//client/proto_rust:client-proto",
        "//crypto/secret_sharing:secret-sharing-noffi",
        "//tvs/proto_rust:tvs-proto",
        "@hats_crate_index//:hex",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak//oak_proto_rust/grpc",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tonic",
    ],
)

rust_test(
    name = "hats-server_test",
    size = "small",
    crate = ":hats-server",
)

rust_library(
    name = "tvs-secret-manager",
    srcs = ["tvs-secret-manager.rs"],
    deps = [
        ":tvs-grpc-client",
        "//client/proto_rust:client-proto",
        "//crypto/secret_sharing:secret-sharing-noffi",
        "@hats_crate_index//:hex",
        "@oak//oak_containers/attestation:oak_containers_attestation",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak//oak_proto_rust/grpc",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:log",
        "@oak_crates_index//:mockall",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tonic",
    ],
)

rust_test(
    name = "tvs-secret-manager_test",
    size = "small",
    crate = ":tvs-secret-manager",
    deps = [
        "@boringssl//rust/bssl-crypto",
    ],
)
