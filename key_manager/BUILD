load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

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
        "//gcp_common:gcp-status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:common",
        "@google_cloud_cpp//:kms",
    ],
)

cc_test(
    name = "gcp-kms-client_test",
    size = "small",
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
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "public-key-fetcher",
    hdrs = [
        "public-key-fetcher.h",
    ],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "public-key-fetcher-gcp",
    srcs = ["public-key-fetcher-gcp.cc"],
    hdrs = [
        "public-key-fetcher.h",
        "public-key-fetcher-gcp.h",
    ],
    deps = [
        "//gcp_common:flags",
        "//gcp_common:gcp-status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:spanner",
    ],
)

cc_test(
    name = "public-key-fetcher-gcp_test",
    size = "small",
    srcs = ["public-key-fetcher-gcp_test.cc"],
    deps = [
        ":public-key-fetcher-gcp",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)

cc_test(
    name = "key-fetcher-local_test",
    size = "small",
    srcs = [":key-fetcher-local_test.cc"],
    deps = [
        ":key-fetcher-local",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:status_matchers",
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
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//gcp_common:flags",
        "//gcp_common:gcp-status",
        "//key_manager:gcp-kms-client",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:kms",
        "@google_cloud_cpp//:spanner",
    ],
)

cc_test(
    name = "key-fetcher-gcp_test",
    size = "small",
    srcs = [":key-fetcher-gcp_test.cc"],
    deps = [
        ":key-fetcher-gcp",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:kms",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)

cc_library(
    name = "key-fetcher-wrapper",
    srcs = ["key-fetcher-wrapper.cc"],
    hdrs = ["key-fetcher-wrapper.h"],
    deps = [
        ":bridge/include",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@cxx.rs//:cxx",
    ] + select({
        "//:gcp": ["//key_manager:key-fetcher-gcp"],
        "//conditions:default": ["//key_manager:key-fetcher-local"],
    }),
)

rust_cxx_bridge(
    name = "bridge",
    src = "rust-key-fetcher.rs",
    deps = [":key-fetcher-wrapper"],
)

rust_library(
    name = "rust-key-fetcher",
    srcs = ["rust-key-fetcher.rs"],
    crate_name = "key_fetcher",
    deps = [
        ":bridge",
        ":key-fetcher-wrapper",
        "@cxx.rs//:cxx",
    ],
)
