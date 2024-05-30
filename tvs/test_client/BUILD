load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
load("//bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tvs-trusted-client",
    srcs = ["tvs-trusted-client.rs"],
    deps = [
        ":build",
        "@hats_crate_index//:cxx",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:prost",
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

rust_cxx_bridge(
    name = "bridge",
    src = "tvs-trusted-client.rs",
    deps = [
        ":tvs-trusted-client",
    ],
)

cc_binary(
    name = "tvs-client_main",
    testonly = True,
    srcs = ["tvs-client_main.cc"],
    deps = [
        ":bridge",
        ":tvs-untrusted-client",
        "//tvs/proto:tvs_cc_grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
    ],
)

cc_library(
    name = "tvs-untrusted-client",
    testonly = True,
    srcs = ["tvs-untrusted-client.cc"],
    hdrs = ["tvs-untrusted-client.h"],
    deps = [
        ":bridge",
        "//tvs/proto:tvs_cc_grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
    ],
)
