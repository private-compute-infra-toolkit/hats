load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "database_main",
    srcs = ["database_main.cc"],
    deps = [
        "//crypto:aead-crypter",
        "//crypto:bridge",
        "//crypto:secret-data",
        "//gcp_common:gcp-status",
        "//key_manager:gcp-kms-client",
        "@boringssl//:crypto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@google_cloud_cpp//:spanner",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)
