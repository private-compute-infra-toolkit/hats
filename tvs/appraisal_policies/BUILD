load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "policy-fetcher-local",
    srcs = ["policy-fetcher-local.cc"],
    hdrs = ["policy-fetcher.h"],
    deps = [
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_test(
    name = "policy-fetcher-local_test",
    size = "small",
    srcs = [":policy-fetcher-local_test.cc"],
    deps = [
        ":policy-fetcher-local",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_library(
    name = "policy-fetcher-gcp",
    srcs = ["policy-fetcher-gcp.cc"],
    hdrs = [
        "policy-fetcher.h",
        "policy-fetcher-gcp.h",
    ],
    deps = [
        "//gcp_common:flags",
        "//gcp_common:gcp-status",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@google_cloud_cpp//:spanner",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)

cc_test(
    name = "policy-fetcher-gcp_test",
    size = "small",
    srcs = [":policy-fetcher-gcp_test.cc"],
    deps = [
        ":policy-fetcher-gcp",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@com_google_absl//absl/status:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@google_cloud_cpp//:spanner",
        "@google_cloud_cpp//:spanner_mocks",
    ],
)

rust_library(
    name = "policy-signature",
    srcs = ["policy-signature.rs"],
    crate_name = "policy_signature",
    deps = [
        ":build",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:p256",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:prost",
    ],
)

rust_test(
    name = "policy-signature_test",
    size = "small",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = "policy-signature",
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
        "//tvs/proto:appraisal_policies_proto",
        "@com_google_protobuf//:protoc",
        "@oak//proto:digest.proto",
        "@oak//proto/attestation:evidence.proto",
        "@oak//proto/attestation:reference_value.proto",
        "@oak//proto/attestation:tcb_version.proto",
    ],
    deps = [
        "@oak_crates_index//:prost-build",
    ],
)

rust_library(
    name = "policy-manager",
    srcs = ["policy-manager.rs"],
    deps = [
        "//tvs/appraisal_policies:policy-signature",
        "@hats_crate_index//:hex",
        "@hats_crate_index//:p256",
        "@oak//oak_attestation_verification:oak_attestation_verification_with_regex",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:prost",
    ],
)

rust_test(
    name = "policy-manager_test",
    compile_data = ["//tvs/test_data:tvs_test_data"],
    crate = ":policy-manager",
)
