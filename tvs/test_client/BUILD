load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "tvs-client_main",
    testonly = True,
    srcs = ["tvs-client_main.cc"],
    deps =
        [
            ":tvs-untrusted-client",
            "//tvs/credentials",
            "@com_github_grpc_grpc//:grpc++",
            "@com_google_absl//absl/flags:flag",
            "@com_google_absl//absl/flags:parse",
            "@com_google_absl//absl/log",
            "@com_google_absl//absl/log:initialize",
            "@com_google_absl//absl/status",
            "@com_google_absl//absl/status:statusor",
            "@com_google_absl//absl/strings",
            "@com_google_protobuf//:protobuf",
            "@com_google_protobuf//src/google/protobuf/io",
        ],
)

cc_binary(
    name = "tvs-client-split_main",
    testonly = True,
    srcs = ["tvs-client-split_main.cc"],
    deps =
        [
            ":tvs-untrusted-client",
            "//crypto:bridge",
            "//tvs/credentials",
            "@com_github_grpc_grpc//:grpc++",
            "@com_google_absl//absl/flags:flag",
            "@com_google_absl//absl/flags:parse",
            "@com_google_absl//absl/log",
            "@com_google_absl//absl/log:initialize",
            "@com_google_absl//absl/status",
            "@com_google_absl//absl/status:statusor",
            "@com_google_absl//absl/strings",
            "@com_google_protobuf//:protobuf",
            "@com_google_protobuf//src/google/protobuf/io",
        ],
)

cc_library(
    name = "tvs-untrusted-client",
    testonly = True,
    srcs = ["tvs-untrusted-client.cc"],
    hdrs = ["tvs-untrusted-client.h"],
    deps = [
        "//client/proto:launcher_cc_grpc",
        "//tvs/client:bridge",
        "//tvs/client:bridge/include",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)
