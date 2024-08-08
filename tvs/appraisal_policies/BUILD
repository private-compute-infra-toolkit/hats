load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "policy-fetcher-local",
    srcs = ["policy-fetcher-local.cc"],
    hdrs = ["policy-fetcher.h"],
    deps = [
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_test(
    name = "policy-fetcher-local_test",
    srcs = [":policy-fetcher-local_test.cc"],
    deps = [
        ":policy-fetcher-local",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_library(
    name = "policy-fetcher-gcp",
    srcs = ["policy-fetcher-gcp.cc"],
    hdrs = [
        "policy-fetcher.h",
        "policy-fetcher-gcp.h",
    ],
    deps = [
        "//gcp_common:flags",
        "//gcp_common:gcp-status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:spanner",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_test(
    name = "policy-fetcher-gcp_test",
    srcs = [":policy-fetcher-gcp_test.cc"],
    deps = [
        ":policy-fetcher-gcp",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)
