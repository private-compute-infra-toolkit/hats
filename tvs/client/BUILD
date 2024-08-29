load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "trusted-client",
    srcs = ["trusted-client.rs"],
    deps = [
        ":build",
        "@cxx.rs//:cxx",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@enclave//crypto",
        "@enclave//handshake",
        "@oak//oak_proto_rust",
        "@hats_crate_index//:hex",
    ],
)

rust_library(
    name = "trusted-client-noffi",
    srcs = ["trusted-client.rs"],
    crate_features = ["noffi"],
    crate_name = "tvs_trusted_client",
    deps = [
        ":build",
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

rust_test(
    name = "trusted-client_test",
    srcs = ["trusted-client.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate_features = ["noffi"],
    deps = [
        "//tvs/trusted_tvs:tvs-trusted",
        ":build",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@enclave//crypto",
        "@enclave//handshake",
        "@oak//oak_proto_rust",
        "//key_manager:rust-key-fetcher",
    ],
)

cargo_build_script(
    name = "build",
    srcs = [
        "build.rs",
    ],
    build_script_env = {
        "OAK_PROTO_INCLUDE": "$(location @oak//proto/attestation:evidence.proto)",
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
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
    src = "trusted-client.rs",
    deps = [
        ":trusted-client",
    ],
)
