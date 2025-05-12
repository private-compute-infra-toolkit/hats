load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "measure",
    srcs = glob(["src/guest/measure/*.rs"]),
    crate_root = "src/guest/measure/mod.rs",
    deps = [
        ":common",
        ":error",
        ":identity",
        "@sev_snp_utils_crate_index//:bytemuck",
        "@sev_snp_utils_crate_index//:libc",
        "@sev_snp_utils_crate_index//:sha2",
        "@sev_snp_utils_crate_index//:uuid",
    ],
)

rust_library(
    name = "identity",
    srcs = ["src/guest/identity/types.rs"],
    deps = [
        ":common",
        ":error",
        "@sev_snp_utils_crate_index//:base64",
        "@sev_snp_utils_crate_index//:bytemuck",
        "@sev_snp_utils_crate_index//:hex",
        "@sev_snp_utils_crate_index//:libc",
        "@sev_snp_utils_crate_index//:once_cell",
    ],
)

rust_library(
    name = "error",
    srcs = ["src/error.rs"],
)

rust_library(
    name = "common",
    srcs = glob(["src/common/*.rs"]),
    crate_root = "src/common/mod.rs",
    deps = [
        ":error",
        "@sev_snp_utils_crate_index//:sha2",
        "@sev_snp_utils_crate_index//:uuid",
    ],
)
