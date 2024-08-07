load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")
load("//bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")

package(
    default_visibility = ["//visibility:public"],
)

rust_binary(
    name = "launcher",
    srcs = [
        "launcher.rs",
    ],
    deps = [
        ":bridge",
        ":server-ffi",
        "@oak//oak_client",
        "@oak//oak_containers_launcher:lib",
        "@oak//oak_crypto",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:env_logger",
        "@oak_crates_index//:tokio",
        "@using_cxx//:cxx",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "launcher.rs",
    deps = [":server-ffi-include"],
)

rust_library(
    name = "certificates",
    srcs = ["certificates.rs"],
    deps = [
        "@hats_crate_index//:reqwest",
        "@hats_crate_index//:sev",
        "@oak_crates_index//:anyhow",
        "@using_cxx//:cxx",
    ],
)

rust_cxx_bridge(
    name = "certificates_bridge",
    src = "certificates.rs",
    deps = [
        "certificates",
    ],
)

cc_binary(
    name = "forwarding-tvs-server_main",
    srcs = ["forwarding-tvs-server_main.cc"],
    deps = [
        ":forwarding-tvs-server",
        "//tvs/credentials",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "forwarding-tvs-server",
    srcs = ["forwarding-tvs-server.cc"],
    hdrs = ["forwarding-tvs-server.h"],
    deps = [
        "//client/launcher:certificates_bridge",
        "//client/launcher:certificates_bridge/include",
        "//client/proto:launcher_cc_grpc",
        "//client/proto:launcher_cc_proto",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@using_cxx//:cxx",
        "@using_cxx//:cxx_cc",
    ],
)

cc_test(
    name = "forwarding-tvs-server_test",
    srcs = ["forwarding-tvs-server_test.cc"],
    data = [
        "//tvs/test_data:tvs_test_data",
    ],
    deps = [
        ":forwarding-tvs-server",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/test_client:tvs-untrusted-client",
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
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_library(
    name = "server-ffi",
    srcs = ["server-ffi.cc"],
    hdrs = ["server-ffi.h"],
    deps = [
        ":forwarding-tvs-server",
        "//tvs/credentials",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_privacysandbox_servers_common//:local_parameters",
        "@google_privacysandbox_servers_common//:local_parc_server",
        "@using_cxx//:cxx_cc",
    ],
)

cc_library(
    name = "server-ffi-include",
    hdrs = ["server-ffi.h"],
    deps = [
        "@using_cxx//:cxx_cc",
    ],
)

cc_library(
    name = "qemu",
    srcs = ["qemu.cc"],
    hdrs = ["qemu.h"],
    deps = [
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
    srcs = ["qemu_test.cc"],
    deps = [
        ":qemu",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)
