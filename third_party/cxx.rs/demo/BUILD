load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//third_party/cxx.rs/tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")

rust_binary(
    name = "demo",
    srcs = glob(["src/**/*.rs"]),
    edition = "2021",
    deps = [
        ":blobstore-sys",
        ":bridge",
        "//third_party/cxx.rs:cxx",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "src/main.rs",
    deps = [":blobstore-include"],
)

cc_library(
    name = "blobstore-sys",
    srcs = ["src/blobstore.cc"],
    deps = [
        ":blobstore-include",
        ":bridge/include",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "blobstore-include",
    hdrs = ["include/blobstore.h"],
    deps = [
        "//third_party/cxx.rs:core",
        "@com_google_absl//absl/status:statusor",
    ],
)
