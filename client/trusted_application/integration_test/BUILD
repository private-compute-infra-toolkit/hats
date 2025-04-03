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

load("@rules_cc//cc:defs.bzl", "cc_binary")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "trusted_application_test",
    testonly = 1,
    srcs = ["trusted_application_test.cc"],
    args = [
        "--minloglevel=0",
        "--stderrthreshold=0",
    ],
    data = [
        "//client/trusted_application/test_data",
    ],
    tags = ["virtualization"],
    deps = [
        "//client/launcher",
        "//client/proto:launcher_config_cc_proto",
        "//client/proto:trusted_service_cc_proto",
        "//client/trusted_application/client:trusted_application_client",
        "//crypto:test-ec-key",
        "//key_manager:test-key-fetcher",
        "//status_macro:status_macros",
        "//status_macro:status_test_macros",
        "//tvs/appraisal_policies:policy-fetcher-local",
        "//tvs/credentials",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/standalone_server:tvs-service",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)
