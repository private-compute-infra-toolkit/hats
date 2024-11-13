load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

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

rust_test(
    name = "crypto_test",
    crate = ":crypto",
)

rust_library(
    name = "crypto_nostd",
    srcs = glob(["src/**"]),
    crate_features = ["rustcrypto"],
    crate_name = "crypto",
    deps = [
        "@enclave_crate_index//:aead",
        "@enclave_crate_index//:aes-gcm",
        "@enclave_crate_index//:ecdsa",
        "@enclave_crate_index//:hkdf",
        "@enclave_crate_index//:p256",
        "@enclave_crate_index//:pkcs8",
        "@enclave_crate_index//:primeorder",
        "@enclave_crate_index//:sha2",
    ],
)

rust_test(
    name = "crypto_nostd_test",
    crate = ":crypto_nostd",
)
