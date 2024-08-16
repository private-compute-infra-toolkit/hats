load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "hats_orchestrator_client",
    srcs = ["hats_orchestrator_client.cc"],
    hdrs = ["hats_orchestrator_client.h"],
    deps = [
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@oak//cc/containers/sdk:common",
        "@oak//cc/containers/sdk:orchestrator_client",
    ],
)

cc_test(
    name = "hats_orchestrator_client_test",
    srcs = ["hats_orchestrator_client_test.cc"],
    deps = [
        ":hats_orchestrator_client",
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "hats_lightweight_client",
    srcs = ["hats_lightweight_client.cc"],
    hdrs = ["hats_lightweight_client.h"],
    deps = [
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "hats_lightweight_client_test",
    srcs = ["hats_lightweight_client_test.cc"],
    deps = [
        ":hats_lightweight_client",
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)
