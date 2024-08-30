load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "tvs-server_main",
    srcs = ["tvs-server_main.cc"],
    deps = [
        ":tvs-server",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/trusted_tvs:bridge",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ] + select({
        "//:gcp": [
            "//key_manager:key-fetcher-gcp",
            "//tvs/appraisal_policies:policy-fetcher-gcp",
        ],
        "//conditions:default": [
            "//key_manager:key-fetcher-local",
            "//tvs/appraisal_policies:policy-fetcher-local",
        ],
    }),
)

cc_library(
    name = "tvs-server",
    srcs = ["tvs-server.cc"],
    hdrs = ["tvs-server.h"],
    deps = [
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/trusted_tvs:bridge",
        "//tvs/trusted_tvs:bridge/include",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "tvs-server_test",
    size = "small",
    srcs = ["tvs-server_test.cc"],
    data = [
        "//tvs/test_data:tvs_test_data",
    ],
    deps = [
        ":tvs-server",
        "//key_manager:key-fetcher-wrapper",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/test_client:tvs-untrusted-client",
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
    ],
)
