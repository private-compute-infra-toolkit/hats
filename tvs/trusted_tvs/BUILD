load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
load("//bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tvs-trusted",
    srcs = ["src/lib.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build",
        "@hats_crate_index//:cxx",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:jwt-simple",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//micro_rpc",
        "@oak//oak_proto_rust",
        "@oak//oak_attestation_verification",
        "@enclave//crypto",
        "@enclave//handshake",
    ],
)

rust_test(
    name = "tvs-trusted_test",
    srcs = ["src/lib.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build",
        "@hats_crate_index//:cxx",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:jwt-simple",
        "@hats_crate_index//:p256",
        # Use the same version oak uses protos generated from a different
        # prost version are not compatible. Here we are referring to the
        # attestation messages.
        "@oak_crates_index//:prost",
        "@oak//micro_rpc",
        "@oak//oak_proto_rust",
        "@oak//oak_attestation_verification",
        "@enclave//handshake",
        "@enclave//crypto",
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
    crate_features = ["bazel"],
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
    src = "src/lib.rs",
    deps = [
        ":tvs-trusted",
    ],
)
