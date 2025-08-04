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

load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

package(
    default_visibility = ["//visibility:public"],
)

exports_files(["oak-syslogd.service"])

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
        "@oak//oak_containers/syslogd:oak_containers_syslogd",
    ],
    # TODO: This doesn't work, due to executables forced to 0755
    # https://github.com/bazelbuild/rules_pkg/issues/822
    # Suggested is to make pkg_files instead, passed as src to pkg_tar
    mode = "0555",
    package_dir = "/usr/bin/",
)

pkg_tar(
    name = "hats_system_image_test_single",
    # Order matters here as we intend to overwrite certain files in Oak's system
    # image. Oak system image should come first.
    allow_duplicates_from_deps = True,
    # buildifier: leave-alone
    deps = [
        "@oak_containers_system_image_base//file:base-image.tar.xz",
        ":admin_bin",
        ":interface",
        "//client/system_image/test_single:services",
        "//client/system_image/test_single:tvs_public_keys",
    ],
)

pkg_tar(
    name = "hats_system_image_test_xor_2",
    # Order matters here as we intend to overwrite certain files in Oak's system
    # image. Oak system image should come first.
    allow_duplicates_from_deps = True,
    # buildifier: leave-alone
    deps = [
        "@oak_containers_system_image_base//file:base-image.tar.xz",
        ":admin_bin",
        ":interface",
        "//client/system_image/test_xor_2:services",
        "//client/system_image/test_xor_2:tvs_public_keys",
    ],
)

pkg_tar(
    name = "hats_system_image_test_shamir_2_of_3",
    # Order matters here as we intend to overwrite certain files in Oak's system
    # image. Oak system image should come first.
    allow_duplicates_from_deps = True,
    # buildifier: leave-alone
    deps = [
        "@oak_containers_system_image_base//file:base-image.tar.xz",
        ":admin_bin",
        ":interface",
        "//client/system_image/test_shamir_2_of_3:services",
        "//client/system_image/test_shamir_2_of_3:tvs_public_keys",
    ],
)

pkg_tar(
    name = "hats_system_image_test_single_1sec_heartbeat",
    # Order matters here as we intend to overwrite certain files in Oak's system
    # image. Oak system image should come first.
    allow_duplicates_from_deps = True,
    # buildifier: leave-alone
    deps = [
        "@oak_containers_system_image_base//file:base-image.tar.xz",
        ":admin_bin",
        ":interface",
        "//client/system_image/test_single_1sec_heartbeat:services",
        "//client/system_image/test_single_1sec_heartbeat:tvs_public_keys",
    ],
)
