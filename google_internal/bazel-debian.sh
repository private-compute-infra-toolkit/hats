#!/usr/bin/env bash
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

# shellcheck disable=all

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

# environment variables supported by cbuild (all optional):
#     WORKSPACE                    Set the path to the workspace (repo root)
#     AWS_ACCESS_KEY_ID            AWS auth token
#     AWS_SECRET_ACCESS_KEY        AWS auth token
#     BAZEL_STARTUP_ARGS           Additional startup arguments to pass to bazel invocations
#     BAZEL_EXTRA_ARGS             Additional command arguments to pass to bazel invocations
#     EXTRA_DOCKER_RUN_ARGS        Additional arguments to pass to docker run invocations

set -euo pipefail

# TODO: Consider which directory to put this.
# internal will be excluded, but this is also ideally temporary

# Exists as a wrapper around builders/tools/bazel-debian
# Ideally, the wrapper isn't needed.
# The wrapper is to allow it to run on everything.
# 1. Build python related things (tar_pkg), avoiding root issues
#    Once bazel-debian is the default dev invocation, WORKSPACE can register the
#    python toolchain by default (which uses bazel-debian python path),
#    and so the patch won't be needed

# Usage: 'google_internal/bazel-debian test //...'

source "patches/apply_patches.sh"
patches::apply_python

# Always revert patches, even if bazel failure or sigint
function cleanup() {
  patches::revert_python
}

trap cleanup EXIT

builders/tools/bazel-debian "$@"; \
