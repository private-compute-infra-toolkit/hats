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

load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
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
        "//crypto:secret-sharing-noffi",
        "@hats_crate_index//:hex",
        "@oak//oak_containers/attestation:oak_containers_attestation",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-util",
    ],
)

rust_library(
    name = "tvs-grpc-client",
    srcs = ["tvs-grpc-client.rs"],
    deps = [
        ":build",
        "//tvs/client:trusted-client-noffi",
        "@hats_crate_index//:hex",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:async-stream",
        "@oak_crates_index//:clap",
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
    srcs = ["tvs-grpc-client.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build-for-test",
        "//tvs/appraisal_policies:policy-manager",
        "//tvs/client:trusted-client-noffi",
        "//tvs/proto_rust:tvs-proto",
        "//tvs/trusted_tvs:key-fetcher",
        "//tvs/trusted_tvs:trusted-tvs",
        "@enclave//crypto",
        "@enclave//handshake",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:async-stream",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:futures",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tokio-vsock",
        "@oak_crates_index//:tonic",
        "@oak_crates_index//:tower",
    ],
)

cargo_build_script(
    name = "build",
    srcs = [
        "build.rs",
    ],
    build_script_env = {
        "DESCRIPTOR_PROTO_PATH": "$(location @com_google_protobuf//:descriptor_proto_srcs)",
        "OAK_PROTO_INCLUDE": "$(location @oak//proto/attestation:evidence.proto)",
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
    },
    data = [
        "//client/proto:launcher.proto",
        "//client/proto:orchestrator_proto",
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:protoc",
        "@com_google_protobuf//:well_known_type_protos",
        "@oak//proto:digest.proto",
        "@oak//proto/attestation:eventlog.proto",
        "@oak//proto/attestation:evidence.proto",
    ],
    deps = [
        "@oak_crates_index//:tonic-build",
    ],
)

cargo_build_script(
    name = "build-for-test",
    srcs = [
        "build-for-test.rs",
    ],
    build_script_env = {
        "DESCRIPTOR_PROTO_PATH": "$(location @com_google_protobuf//:descriptor_proto_srcs)",
        "OAK_PROTO_INCLUDE": "$(location @oak//proto/attestation:evidence.proto)",
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
    },
    data = [
        "//client/proto:launcher.proto",
        "//client/proto:orchestrator_proto",
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:protoc",
        "@com_google_protobuf//:well_known_type_protos",
        "@oak//proto:digest.proto",
        "@oak//proto/attestation:eventlog.proto",
        "@oak//proto/attestation:evidence.proto",
    ],
    deps = [
        "@oak_crates_index//:tonic-build",
    ],
)

rust_library(
    name = "hats-server",
    srcs = ["hats-server.rs"],
    deps = [
        ":build",
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
    srcs = ["hats-server.rs"],
    deps = [
        ":build-for-test",
        ":hats-server",
        "@oak//oak_containers/orchestrator:oak_containers_orchestrator",
        "@oak//oak_proto_rust",
        "@oak//oak_proto_rust/grpc",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:futures",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tonic",
    ],
)
