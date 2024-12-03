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

load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "enclave_main",
    srcs = ["src/main.rs"],
    platform = "@oak//:x86_64-unknown-none",
    deps = [
        "//tvs/trusted_tvs/library:trusted-tvs-enclave",
        "//tvs/trusted_tvs/proto:tvs_enclave",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:log",
    ],
)
