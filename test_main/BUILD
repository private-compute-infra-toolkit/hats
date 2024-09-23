load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "test_main",
    srcs = ["main.cc"],
    deps = [
        "//client/launcher",
        "//client/proto:launcher_config_cc_proto",
        "//client/trusted_application:trusted_application_client",
        "//tvs/credentials",
        "//tvs/proto:appraisal_policies_cc_proto",
        "//tvs/trusted_tvs:bridge",
        "//tvs/untrusted_tvs:tvs-server",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ] + select({
        "//:gcp": [
            "//key_manager:key-fetcher-gcp",
            "//tvs/appraisal_policies:policy-fetcher-gcp",
        ],
        "//conditions:default": [
            "//key_manager:key-fetcher-local",
            "//tvs/appraisal_policies:policy-fetcher-local",
        ],
    }),
)
