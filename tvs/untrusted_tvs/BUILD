cc_binary(
    name = "tvs-server_main",
    srcs = ["tvs-server_main.cc"],
    deps = [
        ":tvs-server",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/trusted_tvs:bridge",
        "//tvs/trusted_tvs:bridge/include",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_protobuf//:protobuf",
        "@oak//proto/attestation:reference_value_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "tvs-server",
    srcs = ["tvs-server.cc"],
    hdrs = ["tvs-server.h"],
    deps = [
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/trusted_tvs:bridge",
        "//tvs/trusted_tvs:bridge/include",
        "@com_github_grpc_grpc//:grpc++",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_test(
    name = "tvs-server_test",
    srcs = ["tvs-server_test.cc"],
    data = [
        "//tvs/test_data:tvs_test_data",
    ],
    deps = [
        ":tvs-server",
        "//tvs/test_client:tvs-untrusted-client",
        "@com_google_googletest//:gtest_main",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)
