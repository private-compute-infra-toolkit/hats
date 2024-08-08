load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "gcp-status",
    srcs = ["gcp-status.cc"],
    hdrs = ["gcp-status.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@google_cloud_cpp//:common",
    ],
)

cc_library(
    name = "flags",
    srcs = ["flags.cc"],
    hdrs = ["flags.h"],
    deps = [
        "@com_google_absl//absl/flags:flag",
    ],
)
