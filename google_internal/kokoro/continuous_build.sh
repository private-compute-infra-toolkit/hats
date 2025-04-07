#!/bin/bash
# Copyright 2025 Google LLC.
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
# export TZ=Etc/UTC
# export PS4='+\t $(basename ${BASH_SOURCE[0]}):${LINENO} ' # xtrace prompt
# set -x

### Stop pushd/popd from printing the stack
pushd() {
  builtin pushd "$@" > /dev/null
}
#shellcheck disable=2120
popd() {
  builtin popd "$@" > /dev/null
}

readonly KOKORO_HATS_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats"

# Install latest bazel, since ubuntu2004 image used has 6.5.0
readonly BAZEL_VERSION=bazel-7.4.1-linux-x86_64
readonly BAZEL_TMP_DIR=/tmpfs/tmp/bazel-release
mkdir -p "${BAZEL_TMP_DIR}"
ln -fs "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}" "${BAZEL_TMP_DIR}/bazel"
chmod 755 "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
export PATH="${BAZEL_TMP_DIR}:${PATH}"

# Apply patches
pushd "${KOKORO_HATS_DIR}"
source "${KOKORO_HATS_DIR}/patches/apply_patches.sh"
patches::apply_python
popd

pushd "${KOKORO_HATS_DIR}"

##### First bazel test all on Kokoro

# Skip builds/tests that fail on Kokoro
# nopresubmit: general tests that Kokoro can't run
# virtualization: builds/tests that require virtualization, such as
#    /dev/kvm, /dev/vhost-vsock, etc.
tag_filters="-nopresubmit,-virtualization"

args=(
  test
  --config=ci
  --verbose_failures=true
  --experimental_convenience_symlinks=ignore
  --build_tag_filters="${tag_filters}"
  --test_tag_filters="${tag_filters}"
  --
  //...
)
./google_internal/kokoro/bazel_wrapper.py "${args[@]}"

popd
