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

package(
    default_visibility = ["//visibility:public"],
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
        "@cxx.rs//:cxx",
    ],
)

rust_library(
    name = "key-fetcher",
    srcs = glob(["src/**"]),
    visibility = [
        "//client/orchestrator:__pkg__",
        "//tvs/client:__pkg__",
        "//tvs/trusted_tvs:__subpackages__",
    ],
    deps = [
        ":key-fetcher-wrapper",
        ":key-fetcher-wrapper-bridge",
        "//tvs/trusted_tvs/types:trusted-tvs-types",
        "@cxx.rs//:cxx",
        "@oak_crates_index//:anyhow",
    ],
)

rust_cxx_bridge(
    name = "key-fetcher-wrapper-bridge",
    src = "src/key_fetcher.rs",
    deps = [
        ":key-fetcher-wrapper",
    ],
)
