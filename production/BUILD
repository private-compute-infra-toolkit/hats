# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_cc//cc:defs.bzl", "cc_binary")
load("@rules_cc_embed_binary//embed_binary:defs.bzl", "cc_embed_binary")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_push")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

cc_embed_binary(
    name = "tvs_database_schema",
    src = "tvs_database_schema.ddl",
)

cc_binary(
    name = "database_main",
    srcs = ["database_main.cc"],
    deps = [
        ":tvs_database_schema",
        "//crypto:aead-crypter",
        "//crypto:ec-key",
        "//crypto:secret-data",
        "//crypto/secret_sharing:bridge",
        "//key_manager:gcp-kms-client",
        "//status_macro:status_macros",
        "//tvs/proto:appraisal_policies_cc_proto",
        "@boringssl//:crypto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//src/google/protobuf/io",
        "@google_cloud_cpp//:spanner",
    ],
)

# TVS binary
pkg_tar(
    name = "tvs_binary",
    srcs = ["//tvs/standalone_server:tvs-server_main"],
    package_dir = "/usr/bin",
)

oci_image(
    name = "tvs_image",
    base = "@distroless_cc_debian12",
    entrypoint = [
        "/usr/bin/tvs-server_main",
    ],
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
)

# Public key server
pkg_tar(
    name = "public_key_server_binary",
    srcs = ["//public_key:public-key-server_main"],
    package_dir = "/usr/bin",
)

oci_image(
    name = "public_key_server_image",
    base = "@distroless_cc_debian12",
    entrypoint = [
        "/usr/bin/public-key-server_main",
        # Spanner database information
        "--bucket_name=ps-hats-playground-public-keys",
        "--project_id=ps-hats-playground",
        "--instance_id=tvs-instance",
        "--database_id=tvs-db",
    ],
    tars = [
        ":public_key_server_binary",
    ],
)

# To push tvs_image to GCP repository, you need to have proper credentials.
# Run the following:
# $ gcloud auth login
# $ gcloud config set project ps-hats-playground
oci_push(
    name = "push_public_key_server_image",
    image = ":public_key_server_image",
    remote_tags = ["latest"],
    repository = "us-docker.pkg.dev/ps-hats-playground/gcr.io/public_key_server_image",
)
