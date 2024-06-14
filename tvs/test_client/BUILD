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
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@enclave//crypto",
        "@enclave//handshake",
        "@oak//oak_proto_rust",
    ],
)

cargo_build_script(
    name = "build",
    srcs = [
        "build.rs",
    ],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
        "OAK_PROTO_INCLUDE": "$(location @oak//proto/attestation:evidence.proto)",
    },
    data = [
        "//tvs/proto:tvs_messages_proto",
        "@com_google_protobuf//:protoc",
        "@oak//proto/attestation:evidence.proto",
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
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
    ],
)

cc_library(
    name = "tvs-untrusted-client",
    testonly = True,
    srcs = ["tvs-untrusted-client.cc"],
    hdrs = ["tvs-untrusted-client.h"],
    deps = [
        ":bridge",
        ":bridge/include",
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)
