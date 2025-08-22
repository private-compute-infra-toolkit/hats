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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "snp-abi",
    hdrs = [
        "snp-abi.h",
        "@psp-sev//file",
    ],
    # ABI library shouldn't be depended on unintentionally.
    visibility = [":noexport"],
)

package_group(
    name = "noexport",
    packages = [
        "//client/launcher/certificates",
        "//client/launcher/kernel-api",
        "//client/launcher/kernel-api-mock",
        "//client/launcher/snp-abi",
    ],
)

cc_library(
    name = "kernel-api",
    srcs = ["kernel-api.cc"],
    hdrs = ["kernel-api.h"],
    deps = [
        ":snp-abi",
    ],
)

cc_library(
    name = "kernel-api-mock",
    testonly = 1,
    hdrs = ["kernel-api-mock.h"],
    deps = [
        ":kernel-api",
        ":snp-abi",
        "@com_google_absl//absl/log:check",
    ],
)

cc_binary(
    name = "launcher_main",
    srcs = ["launcher_main.cc"],
    deps = [
        ":launcher",
        "//client/proto:launcher_config_cc_proto",
        "//status_macro:status_macros",
        "//tvs/credentials",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "launcher",
    srcs = ["launcher.cc"],
    hdrs = ["launcher.h"],
    deps = [
        ":certificates",
        ":launcher-server",
        ":logs-service",
        ":qemu",
        "//client/proto:launcher_cc_proto",
        "//client/proto:launcher_config_cc_proto",
        "//status_macro:status_macros",
        "@com_google_absl//absl/base:nullability",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@libarchive//libarchive:archive",
    ],
)

cc_test(
    name = "launcher_test",
    size = "small",
    srcs = ["launcher_test.cc"],
    data = [
        "//client/test_data/launcher:launcher_test_data",
    ],
    tags = ["virtualization"],
    deps = [
        ":launcher",
        "//client/proto:launcher_cc_grpc",
        "//status_macro:status_macros",
        "//status_macro:status_test_macros",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf_headers",
        "@com_google_protobuf//src/google/protobuf/io",
        "@oak//proto/containers:interfaces_cc_grpc",
        "@oak//proto/containers:interfaces_cc_proto",
    ],
)

cc_library(
    name = "launcher-server",
    srcs = ["launcher-server.cc"],
    hdrs = ["launcher-server.h"],
    deps = [
        "//client/proto:launcher_cc_grpc",
        "//client/proto:launcher_cc_proto",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:empty_cc_proto",
        "@oak//proto/containers:interfaces_cc_grpc",
        "@oak//proto/containers:interfaces_cc_proto",
    ],
)

cc_test(
    name = "launcher-server_test",
    size = "small",
    srcs = ["launcher-server_test.cc"],
    data = [
        "//tvs/test_data:tvs_test_data",
    ],
    defines = select({
        "//:dynamic_attestation_enabled": ["DYNAMIC_ATTESTATION"],
        "//conditions:default": [],
    }),
    deps = [
        ":launcher-server",
        "//client/proto:launcher_cc_proto",
        "//crypto:test-ec-key",
        "//key_manager:test-key-fetcher",
        "//status_macro:status_macros",
        "//status_macro:status_test_macros",
        "//tvs/client:bridge",
        "//tvs/client:bridge/include",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/standalone_server:tvs-service",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf_headers",
        "@com_google_protobuf//src/google/protobuf/io",
        "@oak//proto/attestation:evidence_cc_proto",
        "@oak//proto/containers:interfaces_cc_grpc",
        "@oak//proto/containers:interfaces_cc_proto",
    ] + select({
        "//:dynamic_attestation_enabled": [
            "//tvs/test_utils_cc:policy_generator",
        ],
        "//conditions:default": [],
    }),
)

cc_library(
    name = "vmm-interface",
    hdrs = ["vmm.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "qemu",
    srcs = ["qemu.cc"],
    hdrs = ["qemu.h"],
    deps = [
        ":vmm-interface",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_test(
    name = "qemu_test",
    size = "small",
    srcs = ["qemu_test.cc"],
    deps = [
        ":qemu",
        "//status_macro:status_test_macros",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "certificates",
    srcs = ["certificates.cc"],
    hdrs = ["certificates.h"],
    deps = [
        ":kernel-api",
        ":snp-abi",
        "//status_macro:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@curl",
    ],
)

cc_test(
    name = "certificates_test",
    size = "small",
    srcs = ["certificates_test.cc"],
    data = [
        "//client/test_data/launcher:launcher_test_data",
    ],
    deps = [
        ":certificates",
        ":kernel-api-mock",
        "//status_macro:status_test_macros",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@cpp-httplib//:cpp-httplib",
    ],
)

cc_library(
    name = "logs-service",
    srcs = ["logs-service.cc"],
    hdrs = ["logs-service.h"],
    deps = [
        "@com_github_opentelemetry_proto//:logs_proto_cc",
        "@com_github_opentelemetry_proto//:logs_service_grpc_cc",
        "@com_github_opentelemetry_proto//:logs_service_proto_cc",
        "@com_google_absl//absl/log",
    ],
)

cc_test(
    name = "logs-service_test",
    size = "small",
    srcs = ["logs-service_test.cc"],
    deps = [
        ":logs-service",
        "//status_macro:status_test_macros",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_opentelemetry_proto//:logs_service_grpc_cc",
        "@com_github_opentelemetry_proto//:logs_service_proto_cc",
        "@com_google_absl//absl/base:log_severity",
        "@com_google_absl//absl/log:scoped_mock_log",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)
