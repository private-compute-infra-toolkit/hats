load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_binary")

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
        "@com_google_absl//absl/strings",
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
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

rust_binary(
    name = "launcher",
    srcs = [
        "launcher.rs",
    ],
    deps = [
        ":bridge",
        ":server-ffi",
        "@cxx.rs//:cxx",
        "@oak//oak_client",
        "@oak//oak_containers/launcher:lib",
        "@oak//oak_crypto",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:env_logger",
        "@oak_crates_index//:tokio",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "launcher.rs",
    deps = [":server-ffi-include"],
)

cc_binary(
    name = "launcher_main",
    srcs = ["launcher_main.cc"],
    deps = [
        ":launcher_cc",
        "//client/proto:launcher_config_cc_proto",
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
    name = "launcher_cc",
    srcs = ["launcher.cc"],
    hdrs = ["launcher.h"],
    deps = [
        ":launcher-server",
        ":logs-service",
        ":qemu",
        "//client/proto:launcher_config_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:nullability",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_privacysandbox_servers_common//:local_parameters",
        "@google_privacysandbox_servers_common//:local_parc_server",
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
    # TODO(b/351007909): remove this after deflaking
    # the test.
    tags = ["nopresubmit"],
    deps = [
        ":launcher_cc",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/untrusted_tvs:tvs-server",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf_headers",
        "@com_google_protobuf//src/google/protobuf/io",
    ],
)

cc_library(
    name = "launcher-server",
    srcs = ["launcher-server.cc"],
    hdrs = ["launcher-server.h"],
    deps = [
        ":certificates",
        "//client/proto:launcher_cc_grpc",
        "//client/proto:launcher_cc_proto",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
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
    deps = [
        ":launcher-server",
        "//key_manager:key-fetcher-wrapper",
        "//tvs/client:bridge",
        "//tvs/client:bridge/include",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/untrusted_tvs:tvs-server",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
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
    name = "server-ffi",
    srcs = ["server-ffi.cc"],
    hdrs = ["server-ffi.h"],
    deps = [
        ":launcher-server",
        "//tvs/credentials",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@cxx.rs//:cxx",
        "@google_privacysandbox_servers_common//:local_parameters",
        "@google_privacysandbox_servers_common//:local_parc_server",
    ],
)

cc_library(
    name = "server-ffi-include",
    hdrs = ["server-ffi.h"],
    deps = [
        "@cxx.rs//:cxx",
    ],
)

cc_library(
    name = "qemu",
    srcs = ["qemu.cc"],
    hdrs = ["qemu.h"],
    deps = [
        "//client/proto:launcher_config_cc_proto",
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
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
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
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
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
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status:status_matchers",
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
        "@com_google_absl//absl/log",
        "@opentelemetry-proto//:logs_proto_cc",
        "@opentelemetry-proto//:logs_service_grpc_cc",
        "@opentelemetry-proto//:logs_service_proto_cc",
    ],
)

cc_test(
    name = "logs-service_test",
    size = "small",
    srcs = ["logs-service_test.cc"],
    deps = [
        ":logs-service",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:log_severity",
        "@com_google_absl//absl/log:scoped_mock_log",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
        "@opentelemetry-proto//:logs_service_grpc_cc",
        "@opentelemetry-proto//:logs_service_proto_cc",
    ],
)
