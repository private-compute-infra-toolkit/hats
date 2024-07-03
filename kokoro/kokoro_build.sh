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

# Fail on any error.
set -e

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
set -x

echo "Starting kokoro_build"

BAZEL_VERSION=bazel-7.2.0-linux-x86_64
BAZEL_TMP_DIR=/tmpfs/tmp/bazel-release
mkdir -p "${BAZEL_TMP_DIR}"
echo "Bazel file: ${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
ls "${KOKORO_GFILE_DIR}"
ln -fs "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}" "${BAZEL_TMP_DIR}/bazel"
chmod 755 "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
export PATH="${BAZEL_TMP_DIR}:${PATH}"
# This should show /tmpfs/tmp/bazel-release/bazel
which bazel
KOKORO_LOCAL_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats/kokoro"

# Cd required to be in workspace
cd "${KOKORO_LOCAL_DIR}"
args=(
  test
  --verbose_failures=true
  # --test_output=all
  --symlink_prefix=/
  --
  //...
)
./bazel_wrapper.py "${args[@]}"
