cc_binary(
    name = "tvs-server_main",
    srcs = ["tvs-server_main.cc"],
    deps = [
        ":tvs-server",
        "//tvs/trusted_tvs:bridge",
        "//tvs/trusted_tvs:bridge/include",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
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
    ],
)

cc_test(
    name = "tvs-server_test",
    srcs = ["tvs-server_test.cc"],
    deps = [
        ":tvs-server",
        "//tvs/test_client:tvs-untrusted-client",
        "@com_google_googletest//:gtest_main",
    ],
)
