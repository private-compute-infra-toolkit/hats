load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "public-key-server_main",
    srcs = ["public-key-server_main.cc"],
    deps = [
        ":public-key-server",
        "//key_manager:public-key-fetcher-gcp",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "public-key-server",
    srcs = ["public-key-server.cc"],
    hdrs = ["public-key-server.h"],
    deps = [
        "//key_manager:public-key-fetcher",
        "//public_key/proto:public_key_service_cc_grpc",
        "//public_key/proto:public_key_service_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@curl",
        "@google_cloud_cpp//:storage",
    ],
)

cc_test(
    name = "public-key-server_test",
    size = "small",
    srcs = ["public-key-server_test.cc"],
    deps = [
        ":public-key-server",
        "//key_manager:public-key-fetcher",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf_headers",
        "@com_google_protobuf//src/google/protobuf/io",
        "@cpp-httplib//:cpp-httplib",
        "@google_cloud_cpp//:storage_mocks",
        "@google_cloud_cpp//google/cloud/storage:storage_client_testing",
    ],
)
