load("@rules_cc//cc:defs.bzl", "cc_binary")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_push")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

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

# TVS binary
pkg_tar(
    name = "tvs_binary",
    srcs = ["//tvs/untrusted_tvs:tvs-server_main"],
    package_dir = "/usr/bin",
    tags = ["nopresubmit"],
)

oci_image(
    name = "tvs_image",
    base = "@distroless_cc_debian12",
    entrypoint = [
        "/usr/bin/tvs-server_main",
        # Spanner database information
        "--project_id=ps-hats-playground",
        "--instance_id=tvs-instance",
        "--database_id=tvs-db",
    ],
    tags = ["nopresubmit"],
    tars = [
        ":tvs_binary",
    ],
)

# To push tvs_image to GCP repository, you need to have proper credentials.
# Run the following:
# $ gcloud auth login
# $ gcloud config set project ps-hats-playground
oci_push(
    name = "push_tvs_image",
    image = ":tvs_image",
    remote_tags = ["latest"],
    repository = "us-docker.pkg.dev/ps-hats-playground/gcr.io/tvs_image",
    tags = ["nopresubmit"],
)
