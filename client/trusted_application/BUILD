load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "main",
    srcs = ["main.cc"],
    deps = [
        ":trusted_application",
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//client/sdk:hats_orchestrator_client",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "trusted_application",
    srcs = ["trusted_application.cc"],
    hdrs = ["trusted_application.h"],
    deps = [
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//client/sdk:hats_orchestrator_client",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)
