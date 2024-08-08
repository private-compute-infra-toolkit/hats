load("@rules_cc//cc:defs.bzl", "cc_binary")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "database_main",
    srcs = ["database_main.cc"],
    deps = [
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "//key_manager:gcp-kms-client",
        "//key_manager:gcp-status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:spanner",
    ],
)
