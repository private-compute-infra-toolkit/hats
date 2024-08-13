load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "launcher_proto",
    srcs = ["launcher.proto"],
    deps = [
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:empty_proto",
    ],
)

cc_grpc_library(
    name = "launcher_cc_grpc",
    srcs = [":launcher_proto"],
    grpc_only = True,
    tags = ["grpc"],
    deps = [":launcher_cc_proto"],
)

cc_proto_library(
    name = "launcher_cc_proto",
    deps = ["launcher_proto"],
)

proto_library(
    name = "launcher_config_proto",
    srcs = ["launcher_config.proto"],
)

cc_proto_library(
    name = "launcher_config_cc_proto",
    deps = ["launcher_config_proto"],
)

proto_library(
    name = "orchestrator_proto",
    srcs = ["orchestrator.proto"],
    deps = [
        "@com_google_protobuf//:empty_proto",
    ],
)

cc_proto_library(
    name = "orchestrator_cc_proto",
    deps = ["orchestrator_proto"],
)

cc_grpc_library(
    name = "orchestrator_cc_grpc",
    srcs = [":orchestrator_proto"],
    grpc_only = True,
    tags = ["grpc"],
    deps = [":orchestrator_cc_proto"],
)
