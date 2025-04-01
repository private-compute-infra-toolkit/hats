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
        "//client/system_image:oak-syslogd.service",
    ],
    package_dir = "/etc/systemd/system/",
)
