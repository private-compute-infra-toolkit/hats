load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test", "rust_binary")

package (
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "handshake",
    srcs = glob(["src/**"]),
    deps = [
        "//crypto:crypto",
        "@enclave_crate_index//:static_assertions",
    ],
)
