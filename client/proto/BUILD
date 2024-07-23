load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "launcher_proto",
    srcs = ["launcher.proto"],
    deps = [
        "//tvs/proto:tvs_messages_proto",
    ],
)

cc_proto_library(
    name = "launcher_cc_proto",
    deps = ["launcher_proto"],
)

cc_grpc_library(
    name = "launcher_cc_grpc",
    srcs = [":launcher_proto"],
    grpc_only = True,
    tags = ["grpc"],
    deps = [":launcher_cc_proto"],
)
