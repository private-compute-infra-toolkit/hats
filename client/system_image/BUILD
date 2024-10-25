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

load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

package(
    default_visibility = ["//visibility:public"],
)

pkg_tar(
    name = "tvs_public_keys",
    srcs = ["tvs_public_keys.txt"],
    package_dir = "/hats/",
)

# Change oak-orchestrator.service to load hats orchestrator
# and bake the TVS public key in the file.
pkg_tar(
    name = "services",
    srcs = [
        "oak-orchestrator.service",
        "oak-syslogd.service",
    ],
    package_dir = "/etc/systemd/system/",
)

# Override the enp0s1 interface settings as we are setting
# the networking through kernel NFS flags.
pkg_tar(
    name = "interface",
    srcs = ["10-enp0s1.network"],
    package_dir = "/etc/systemd/network/",
)

# Administrative binaries.
pkg_tar(
    name = "admin_bin",
    srcs = [
        "//client/orchestrator:orchestrator_main",
        "@oak//oak_containers/agent:bin/oak_containers_agent",
    ] + select({
        # Use syslogd from the `prebuilt` directory. This requires the user
        # to run ./client/build-for-hats.sh.
        "//:syslogd_from_binary": ["//client/prebuilt:oak_containers_syslogd"],
        # Build syslogd only if the user specifically enabled it
        # oak_containers_syslogd requires libsystemd.so during the
        # build, which might not exists.
        "//:syslogd_from_source": ["@oak//oak_containers/syslogd:oak_containers_syslogd"],
        "//conditions:default": [],
    }),
    package_dir = "/usr/bin/",
)

oci_image(
    name = "hats_system_oci_image",
    base = "@oak_containers_sysimage_base",
    tars = [
        ":admin_bin",
        ":services",
        ":interface",
        ":tvs_public_keys",
    ],
)

oci_runtime_bundle(
    name = "hats_system_image",
    image = ":hats_system_oci_image",
    rootfs_only = True,
)
