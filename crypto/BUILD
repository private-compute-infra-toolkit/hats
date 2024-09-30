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
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "secret-sharing",
    srcs = ["secret-sharing.rs"],
    deps = [
        "@boringssl//rust/bssl-crypto",
        "@cxx.rs//:cxx",
        "@enclave//crypto",
        "@hats_crate_index//:num-bigint",
        "@hats_crate_index//:rand",
        "@hats_crate_index//:serde",
        "@hats_crate_index//:serde_json",
        "@oak_crates_index//:anyhow",
    ],
)

rust_library(
    name = "secret-sharing-noffi",
    srcs = ["secret-sharing.rs"],
    crate_features = ["noffi"],
    crate_name = "secret_sharing",
    deps = [
        "@boringssl//rust/bssl-crypto",
        "@enclave//crypto",
        "@hats_crate_index//:num-bigint",
        "@hats_crate_index//:rand",
        "@hats_crate_index//:serde",
        "@hats_crate_index//:serde_json",
        "@oak_crates_index//:anyhow",
    ],
)

rust_test(
    name = "secret-sharing_test",
    size = "small",
    srcs = ["secret-sharing.rs"],
    deps = [
        "@boringssl//rust/bssl-crypto",
        "@cxx.rs//:cxx",
        "@enclave//crypto",
        "@hats_crate_index//:num-bigint",
        "@hats_crate_index//:rand",
        "@hats_crate_index//:serde",
        "@hats_crate_index//:serde_json",
        "@oak_crates_index//:anyhow",
    ],
)

rust_library(
    name = "crypto-provider",
    srcs = ["crypto-provider.rs"],
    deps = [
        "@hats_crate_index//:rand_core",
        "@hats_crate_index//:thiserror",
    ],
)

cc_library(
    name = "secret-data",
    srcs = ["secret-data.cc"],
    hdrs = ["secret-data.h"],
    deps = [
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:string_view",
    ],
)

cc_test(
    name = "secret-data_test",
    size = "small",
    srcs = ["secret-data_test.cc"],
    deps = [
        ":secret-data",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "aead-crypter",
    srcs = ["aead-crypter.cc"],
    hdrs = ["aead-crypter.h"],
    deps = [
        ":secret-data",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aead-crypter_test",
    size = "small",
    srcs = ["aead-crypter_test.cc"],
    deps = [
        ":aead-crypter",
        ":secret-data",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "secret-sharing.rs",
    deps = [
        ":secret-sharing",
    ],
)
