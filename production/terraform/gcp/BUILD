# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_pkg//:mappings.bzl", "pkg_files")
load("@rules_pkg//:pkg.bzl", "pkg_tar")

pkg_files(
    name = "readme",
    srcs = [
        "README.md",
    ],
    prefix = "/",
)

# Set of Terraform files for deployment without binaries.
common_files = [
    ":readme",
]

tvs_files = [
    "//production/terraform/gcp/applications:tvs_applications_pkg",
    "//production/terraform/gcp/environments/demo:tvs_demo",
    "//production/terraform/gcp/environments/shared:tvs_shared",
    "//production/terraform/gcp/modules:tvs_modules_pkg",
]

# Tarball containing only files for TVS deployment.
pkg_tar(
    name = "tvs_tar",
    srcs = common_files + tvs_files,
    extension = "tgz",
    strip_prefix = "/",
)
