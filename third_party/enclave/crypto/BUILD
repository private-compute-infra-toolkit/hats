load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test", "rust_binary")

package (
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "crypto",
    srcs = glob(["src/**"]),
    deps = [
        "@boringssl//rust/bssl-crypto:bssl-crypto",
    ],
    crate_features=["bssl"],
)
