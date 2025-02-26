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

load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "main",
    srcs = ["main.cc"],
    deps = [
        ":trusted_application",
        "//client/proto:orchestrator_cc_proto",
        "//client/sdk:hats_orchestrator_client",
        "//status_macro:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
    ],
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
        ":trusted_application_client",
        "//client/launcher",
        "//client/proto:launcher_config_cc_proto",
        "//client/proto:trusted_service_cc_proto",
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

cc_library(
    name = "trusted_application",
    srcs = ["trusted_application.cc"],
    hdrs = ["trusted_application.h"],
    deps = [
        "//client/proto:orchestrator_cc_proto",
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//status_macro:status_macros",
        "//status_macro:status_util",
    ],
)

cc_library(
    name = "trusted_application_client",
    testonly = 1,
    srcs = ["trusted_application_client.cc"],
    hdrs = ["trusted_application_client.h"],
    deps = [
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//status_macro:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
    ],
)

cc_binary(
    name = "trusted_application_client_main",
    testonly = 1,
    srcs = ["trusted_application_client_main.cc"],
    deps = [
        ":trusted_application_client",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/strings",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [":main"],
    package_dir = "/usr/local/bin",
    visibility = [
        "//visibility:public",
    ],
)

oci_image(
    name = "image",
    base = "@distroless_cc_debian12",
    entrypoint = ["/usr/local/bin/main"],
    tars = [":tar"],
)

oci_runtime_bundle(
    name = "bundle",
    image = ":image",
)
