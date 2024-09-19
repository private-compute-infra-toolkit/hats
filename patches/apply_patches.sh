#!/bin/bash
# Copyright 2024 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##########
# Run at base directory, i.e. "hats/"

### Common
# common needs to be pulled via sso/rpc, to apply patches
# Instead, manually patch the local copy, and update Workspace to point to
# the local copy.

function patches::apply_common() {
  # Apply patch
  cd "submodules/common" || exit
  git apply ../../patches/parc/parc.patch
  cd ../..

  # Find
  FIRST_LINE="$(($(grep -Fn 'name = "google_privacysandbox_servers_common"' WORKSPACE | cut --delimiter=":" --fields=1) - 1))"
  DELTA="$(awk -v first=${FIRST_LINE} 'NR>first' WORKSPACE | grep -Fn ')' -m 1 | cut --delimiter=":" --fields=1)"
  LAST_LINE="$((FIRST_LINE + DELTA))"

  # Comment out
  sed -i "${FIRST_LINE},${LAST_LINE}{s/^/#/}" WORKSPACE

  # Add local version after
  sed -i "$((LAST_LINE+1))i local_repository\(\n\tname = \"google_privacysandbox_servers_common\",\n\tpath = \"submodules\/common\",\n)" WORKSPACE
}

function patches::revert_common() {
  # Revert patch
  cd "submodules/common" || exit
  git apply -R ../../patches/parc/parc.patch
  cd ../..

  # Find
  FIRST_LINE="$(($(grep -Fn 'name = "google_privacysandbox_servers_common"' WORKSPACE -m 1 | cut --delimiter=":" --fields=1) - 1))"
  DELTA="$(awk -v first=${FIRST_LINE} 'NR>first' WORKSPACE | grep -Fn ')' -m 1 | cut --delimiter=":" --fields=1)"
  LAST_LINE="$((FIRST_LINE + DELTA))"

  # Uncomment original
  sed -i "${FIRST_LINE},${LAST_LINE}{s/#//}" WORKSPACE

  # Delete local version
  sed -i "$((LAST_LINE+1)),$((LAST_LINE+1+3))d" WORKSPACE
}

### Python
# Pkg_tar runs python in the background, which can't run as root.
# So for docker-based builds, this registers toolchains.
# builders/bazel/BUILD hard-codes the path to python3, so updates that if needed
# Default state is to not register any toolchain, as that would default to the
# builders submodule's path for bazel-debian. Once bazel-debian is default, it
# can be the standard behavior (no patch), and only patch for Kokoro (or normal
# bazel)

function patches::apply_python() {
  # Point to correct python path
  sed -i "s@/opt/bin/python3@$(which python3)@" builders/bazel/BUILD
  # Add register_toolchain
  sed -i 's@python_deps()@python_deps()\nload("//builders/bazel:deps.bzl", "python_register_toolchains")\npython_register_toolchains("//builders/bazel")@' WORKSPACE
}

function patches::revert_python() {
  # Reset path
  sed -i "s@$(which python3)@/opt/bin/python3@" builders/bazel/BUILD
  # Remove register toolchain
  sed -i '/load("\/\/builders\/bazel:deps.bzl", "python_register_toolchains")/d' WORKSPACE
  sed -i '/python_register_toolchains("\/\/builders\/bazel")/d' WORKSPACE
}
