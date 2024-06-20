package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "gcp-kms-client",
    srcs = ["gcp-kms-client.cc"],
    hdrs = [
        "gcp-kms-client.h",
        "kms-client.h",
    ],
    deps = [
        "//tvs/proto:tvs_cc_grpc",
        "//tvs/proto:tvs_messages_cc_proto",
        "//tvs/trusted_tvs:bridge",
        "//tvs/trusted_tvs:bridge/include",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@google_cloud_cpp//:kms",
        "@oak//proto/attestation:reference_value_cc_proto",
    ],
)