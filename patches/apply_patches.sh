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
