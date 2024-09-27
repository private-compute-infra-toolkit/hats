load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "main",
    srcs = ["main.cc"],
    deps = [
        ":trusted_application",
        "//client/proto:orchestrator_cc_grpc",
        "//client/proto:orchestrator_cc_proto",
        "//client/sdk:hats_orchestrator_client",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "trusted_application",
    srcs = ["trusted_application.cc"],
    hdrs = ["trusted_application.h"],
    deps = [
        "//client/proto:orchestrator_cc_proto",
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "trusted_application_client",
    srcs = ["trusted_application_client.cc"],
    hdrs = ["trusted_application_client.h"],
    deps = [
        "//client/proto:trusted_service_cc_grpc",
        "//client/proto:trusted_service_cc_proto",
        "//crypto:aead-crypter",
        "//crypto:secret-data",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
    ],
)

pkg_tar(
    name = "tar",
    srcs = [":main"],
    package_dir = "/usr/local/bin",
    visibility = [
        "//visibility:public",
    ],
)

oci_image(
    name = "image",
    base = "@distroless_cc_debian12",
    entrypoint = ["/usr/local/bin/main"],
    tars = [":tar"],
)

oci_runtime_bundle(
    name = "bundle",
    image = ":image",
)
