load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "handshake",
    srcs = glob(["src/**"]),
    deps = [
        "//crypto",
        "@enclave_crate_index//:static_assertions",
    ],
)

rust_test(
    name = "handshake_test",
    srcs = glob(["src/**"]),
    deps = [
        "//crypto",
        "@enclave_crate_index//:hex",
        "@enclave_crate_index//:static_assertions",
    ],
)
