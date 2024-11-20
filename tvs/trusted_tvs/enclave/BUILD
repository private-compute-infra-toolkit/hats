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

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

rust_binary(
    name = "enclave_main",
    srcs = ["enclave_main.rs"],
    platform = "@oak//:x86_64-unknown-none",
    deps = [
        ":enclave_service",
        "//tvs/proto_rust:tvs-proto",
        "//tvs/trusted_tvs:key-provider",
        "//tvs/trusted_tvs:trusted-tvs-enclave",
        "//tvs/trusted_tvs/enclave/proto:tvs_enclave",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:log",
        "@oak_crates_index//:prost",
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
