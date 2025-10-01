load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_proc_macro")

rust_library(
    name = "cxx",
    srcs = glob(["src/**/*.rs"]),
    crate_features = [
        "alloc",
        "std",
    ],
    edition = "2021",
    proc_macro_deps = [
        ":cxxbridge-macro",
    ],
    visibility = ["//visibility:public"],
    deps = [":core-lib"],
    tags = ["no-clippy"],
)

alias(
    name = "codegen",
    actual = ":cxxbridge",
    visibility = ["//visibility:public"],
)

rust_binary(
    name = "cxxbridge",
    srcs = glob(["gen/cmd/src/**/*.rs"]),
    compile_data = ["gen/cmd/src/gen/include/cxx.h"],
    edition = "2021",
    deps = [
        "@crates.io//:clap",
        "@crates.io//:codespan-reporting",
        "@crates.io//:proc-macro2",
        "@crates.io//:quote",
        "@crates.io//:syn",
    ],
    tags = ["no-clippy"],
)

cc_library(
    name = "core",
    hdrs = ["include/cxx.h"],
    include_prefix = "rust",
    strip_include_prefix = "include",
    visibility = ["//visibility:public"],
    tags = ["no-clippy"],
)

cc_library(
    name = "core-lib",
    srcs = ["src/cxx.cc"],
    hdrs = ["include/cxx.h"],
    deps = ["@com_google_absl//absl/status:statusor"],
    tags = ["no-clippy"],
)

rust_proc_macro(
    name = "cxxbridge-macro",
    srcs = glob(["macro/src/**/*.rs"]),
    edition = "2021",
    deps = [
        "@crates.io//:proc-macro2",
        "@crates.io//:quote",
        "@crates.io//:syn",
    ],
    tags = ["no-clippy"],
)

rust_library(
    name = "cxx-build",
    srcs = glob(["gen/build/src/**/*.rs"]),
    compile_data = ["gen/build/src/gen/include/cxx.h"],
    edition = "2021",
    deps = [
        "@crates.io//:cc",
        "@crates.io//:codespan-reporting",
        "@crates.io//:once_cell",
        "@crates.io//:proc-macro2",
        "@crates.io//:quote",
        "@crates.io//:scratch",
        "@crates.io//:syn",
    ],
    tags = ["no-clippy"],
)

rust_library(
    name = "cxx-gen",
    srcs = glob(["gen/lib/src/**/*.rs"]),
    compile_data = ["gen/lib/src/gen/include/cxx.h"],
    edition = "2021",
    visibility = ["//visibility:public"],
    deps = [
        "@crates.io//:cc",
        "@crates.io//:codespan-reporting",
        "@crates.io//:proc-macro2",
        "@crates.io//:quote",
        "@crates.io//:syn",
    ],
    tags = ["no-clippy"],
)
