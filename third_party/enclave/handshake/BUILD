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
    crate = ":handshake",
    deps = [
        "@enclave_crate_index//:hex",
    ],
)

rust_library(
    name = "handshake_nostd",
    srcs = glob(["src/**"]),
    deps = [
        "//crypto:crypto_nostd",
        "@enclave_crate_index//:static_assertions",
    ],
)

rust_test(
    name = "handshake_nostd_test",
    crate = ":handshake_nostd",
    deps = [
        "@enclave_crate_index//:hex",
    ],
)
