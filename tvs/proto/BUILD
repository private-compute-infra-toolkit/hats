load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "tvs_messages_proto",
    srcs = ["tvs_messages.proto"],
    deps = [
        "@oak//proto/attestation:evidence_proto",
    ],
)

cc_proto_library(
    name = "tvs_messages_cc_proto",
    deps = [":tvs_messages_proto"],
)

proto_library(
    name = "tvs_proto",
    srcs = ["tvs.proto"],
    deps = [":tvs_messages_proto"],
)

cc_proto_library(
    name = "tvs_cc_proto",
    deps = ["tvs_proto"],
)

cc_grpc_library(
    name = "tvs_cc_grpc",
    srcs = ["tvs_proto"],
    grpc_only = True,
    tags = ["grpc"],
    deps = [":tvs_cc_proto"],
)

proto_library(
    name = "appraisal_policies_proto",
    srcs = ["appraisal_policies.proto"],
    deps = [
        "@oak//proto/attestation:reference_value_proto",
        "@oak//proto/attestation:tcb_version_proto",
    ],
)

cc_proto_library(
    name = "appraisal_policies_cc_proto",
    deps = [":appraisal_policies_proto"],
)
