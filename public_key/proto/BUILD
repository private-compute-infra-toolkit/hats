load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "public_key_service_proto",
    srcs = ["public_key_service.proto"],
    deps = [
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:empty_proto",
    ],
)

cc_grpc_library(
    name = "public_key_service_cc_grpc",
    srcs = [":public_key_service_proto"],
    grpc_only = True,
    tags = ["grpc"],
    deps = [":public_key_service_cc_proto"],
)

cc_proto_library(
    name = "public_key_service_cc_proto",
    deps = ["public_key_service_proto"],
)
