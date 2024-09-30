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
load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tvs-trusted",
    srcs = ["tvs-trusted.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build",
        "//tvs/appraisal_policies:policy-signature",
        "@hats_crate_index//:hex",
        "@cxx.rs//:cxx",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//oak_proto_rust",
        "@oak//oak_attestation_verification:oak_attestation_verification_with_regex",
        "@enclave//crypto",
        "@enclave//handshake",
        "//key_manager:rust-key-fetcher",
    ],
)

rust_test(
    name = "tvs-trusted_test",
    size = "small",
    srcs = ["tvs-trusted.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build",
        "@cxx.rs//:cxx",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:p256",
        "//tvs/appraisal_policies:policy-signature",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//oak_proto_rust",
        "@oak//oak_attestation_verification",
        "@enclave//handshake",
        "@enclave//crypto",
        "//key_manager:rust-key-fetcher",
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
        "//tvs/proto:appraisal_policies_proto",
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:protoc",
        "@com_google_protobuf//:well_known_type_protos",
        "@oak//proto:digest.proto",
        "@oak//proto/attestation:eventlog.proto",
        "@oak//proto/attestation:evidence.proto",
        "@oak//proto/attestation:reference_value.proto",
        "@oak//proto/attestation:tcb_version.proto",
    ],
    deps = [
        "@oak_crates_index//:prost-build",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "tvs-trusted.rs",
    deps = [
        ":tvs-trusted",
    ],
)
