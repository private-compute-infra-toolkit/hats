load("@rules_rust//rust:defs.bzl", "rust_binary")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "gcp-kms-client",
    srcs = ["gcp-kms-client.cc"],
    hdrs = [
        "gcp-kms-client.h",
        "kms-client.h",
    ],
    deps = [
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/trusted_tvs:bridge",
        "//tvs/trusted_tvs:bridge/include",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@google_cloud_cpp//:kms",
    ],
)

cc_test(
    name = "gcp-kms-client_test",
    srcs = ["gcp-kms-client_test.cc"],
    deps = [
        ":gcp-kms-client",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf_headers",
        "@com_google_protobuf//src/google/protobuf/io",
        "@google_cloud_cpp//:kms",
        "@google_cloud_cpp//:kms_mocks",
    ],
)

rust_binary(
    name = "key-gen",
    srcs = ["key-gen.rs"],
    deps = [
        "@enclave//crypto",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:hpke",
        "@hats_crate_index//:rand",
        "@oak_crates_index//:clap",
    ],
)

cc_library(
    name = "key-fetcher-local",
    srcs = ["key-fetcher-local.cc"],
    hdrs = ["key-fetcher.h"],
    deps = [
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "key-fetcher-local_test",
    srcs = [":key-fetcher-local_test.cc"],
    deps = [
        ":key-fetcher-local",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "key-fetcher-gcp",
    srcs = ["key-fetcher-gcp.cc"],
    hdrs = [
        "key-fetcher.h",
        "key-fetcher-gcp.h",
    ],
    deps = [
        "//key_manager:gcp-kms-client",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:kms",
    ],
)

cc_test(
    name = "key-fetcher-gcp_test",
    srcs = [":key-fetcher-gcp_test.cc"],
    deps = [
        ":key-fetcher-gcp",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:kms",
    ],
)
