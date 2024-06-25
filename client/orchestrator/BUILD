load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

rust_binary(
    name = "orchestrator_main",
    srcs = ["orchestrator_main.rs"],
    deps = [
        ":build",
        ":tvs-grpc-client",
        "@oak//oak_containers_orchestrator:lib",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-util",
    ],
)

rust_library(
    name = "tvs-grpc-client",
    srcs = ["tvs-grpc-client.rs"],
    deps = [
        ":build",
        "//tvs/client:trusted-client-noffi",
        "@hats_crate_index//:hex",
        "@oak//oak_containers_orchestrator:lib",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:async-stream",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tonic",
    ],
)

rust_test(
    name = "tvs-grpc-client_test",
    srcs = ["tvs-grpc-client.rs"],
    compile_data = ["//tvs/test_data:tvs_test_data"],
    deps = [
        ":build-for-test",
        "//tvs/client:trusted-client-noffi",
        "//tvs/trusted_tvs:tvs-trusted",
        "@enclave//crypto",
        "@enclave//handshake",
        "@oak//oak_containers_orchestrator:lib",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:async-stream",
        "@oak_crates_index//:clap",
        "@oak_crates_index//:futures",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:nix",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tokio-util",
        "@oak_crates_index//:tonic",
        "@oak_crates_index//:tower",
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
        "//tvs/proto:tvs_proto",
        "@oak//proto/attestation:evidence.proto",
    ],
    tools = [
        "@com_google_protobuf//:protoc",
    ],
    deps = [
        "@oak//oak_grpc_utils",
        "@oak_crates_index//:prost-build",
    ],
)

cargo_build_script(
    name = "build-for-test",
    srcs = [
        "build-for-test.rs",
    ],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
        "OAK_PROTO_INCLUDE": "$(location @oak//proto/attestation:evidence.proto)",
    },
    data = [
        "//tvs/proto:tvs_proto",
        "@oak//proto/attestation:evidence.proto",
    ],
    tools = [
        "@com_google_protobuf//:protoc",
    ],
    deps = [
        "@oak//oak_grpc_utils",
        "@oak_crates_index//:prost-build",
    ],
)
