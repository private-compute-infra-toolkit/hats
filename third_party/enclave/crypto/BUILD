load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "crypto",
    srcs = glob(["src/**"]),
    crate_features = ["bssl"],
    deps = [
        "@boringssl//rust/bssl-crypto",
    ],
)
