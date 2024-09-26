load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "kv-test-client_main",
    srcs = ["kv-test-client_main.cc"],
    deps = [
        "@com_github_google_quiche//quiche:binary_http_unstable_api",
        "@com_github_google_quiche//quiche:oblivious_http_unstable_api",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@kv-server//public/query/v2:get_values_v2_cc_grpc",
        "@kv-server//public/query/v2:get_values_v2_cc_proto",
    ],
)
