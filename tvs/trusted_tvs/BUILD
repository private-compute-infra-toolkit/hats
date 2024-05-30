load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
load("//bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tvs-trusted",
    srcs = ["src/lib.rs"],
    deps = [
        ":build",
        "@hats_crate_index//:cxx",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:jwt-simple",
        "@hats_crate_index//:prost",
        "@oak//micro_rpc",
        "@oak//oak_crypto",
    ],
)

rust_cxx_bridge(
    name = "bridge",
    src = "src/lib.rs",
    deps = [
        ":tvs-trusted",
    ],
)

rust_test(
    name = "tvs-trusted_test",
    srcs = ["src/lib.rs"],
    deps = [
        ":build",
        "@hats_crate_index//:cxx",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:jwt-simple",
        "@hats_crate_index//:prost",
        "@oak//micro_rpc",
        "@oak//oak_crypto",
    ],
)

cargo_build_script(
    name = "build",
    srcs = [
        "build.rs",
    ],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
    },
    data = [
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:protoc",
    ],
    deps = [
        "@oak//micro_rpc_build",
        "@oak_crates_index//:prost-build",
    ],
)
