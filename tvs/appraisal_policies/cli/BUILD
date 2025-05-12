# Copyright 2025 Google LLC
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

package(
    default_visibility = ["//visibility:public"],
)

rust_binary(
    name = "cli",
    srcs = ["src/main.rs"],
    deps = [
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:env_logger",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:log",
        "@oak_crates_index//:sha2",
        "@oak_crates_index//:tar",
        "@oak_crates_index//:tempfile",
        "@oak_crates_index//:zerocopy",
        "@sev-snp-utils//:common",
        "@sev-snp-utils//:error",
        "@sev-snp-utils//:identity",
        "@sev-snp-utils//:measure",
    ],
)
