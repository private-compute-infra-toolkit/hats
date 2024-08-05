load("@rules_rust//rust:defs.bzl", "rust_binary")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "secret-data",
    srcs = ["secret-data.cc"],
    hdrs = ["secret-data.h"],
    deps = [
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
    ],
)

cc_test(
    name = "secret-data_test",
    srcs = ["secret-data_test.cc"],
    deps = [
        ":secret-data",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "aead-crypter",
    srcs = ["aead-crypter.cc"],
    hdrs = ["aead-crypter.h"],
    deps = [
        ":secret-data",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aead-crypter_test",
    srcs = ["aead-crypter_test.cc"],
    deps = [
        ":aead-crypter",
        ":secret-data",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)
