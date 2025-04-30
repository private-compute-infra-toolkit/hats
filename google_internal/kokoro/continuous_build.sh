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
readonly HATS_SWARMING_DIR="${KOKORO_HATS_DIR}/google_internal/swarming"

# Install latest bazel, since ubuntu2004 image used has 6.5.0
readonly BAZEL_VERSION=bazel-7.4.1-linux-x86_64
readonly BAZEL_TMP_DIR=/tmpfs/tmp/bazel-release
mkdir -p "${BAZEL_TMP_DIR}"
ln -fs "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}" "${BAZEL_TMP_DIR}/bazel"
chmod 755 "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
export PATH="${BAZEL_TMP_DIR}:${PATH}"

pushd "${KOKORO_HATS_DIR}"

################ Test on Kokoro
echo "Testing on Kokoro"

# Skip builds/tests that fail on Kokoro
# nopresubmit: general tests that Kokoro can't run
# virtualization: builds/tests that require virtualization, such as
#    /dev/kvm, /dev/vhost-vsock, etc.
tag_filters="-nopresubmit,-virtualization"

args=(
  test
  --config=ci
  --verbose_failures=true
  --dynamic_mode=off # Static build now as pre-build for swarming
  --build_tag_filters="${tag_filters}"
  --test_tag_filters="${tag_filters}"
  --
  //...
)
./google_internal/kokoro/bazel_wrapper.py "${args[@]}"

################ Test on Swarming
##### Build for swarming
echo "Building for swarming"

# TODO(b/395680242): Resolve RBE on GCP_UBUNTU_DOCKER.
# RBE doesn't auth correctly, but also still runs without it.

args=(
  build
  --config=ci
  --verbose_failures=true
  --dynamic_mode=off # Force static build, for binaries sent to bot
  --build_tag_filters="virtualization"
  --test_tag_filters="virtualization"
  --
  //...
)
./google_internal/kokoro/bazel_wrapper.py "${args[@]}"

popd

# TODO(b/371300767): Also build supporting files via script

##### Copy binaries to directory

pushd "${KOKORO_HATS_DIR}"

# TODO(b/371300767): Trusted application tests
readonly TESTS_LIST=(
  "client/launcher/launcher_test"
)

# Path within test_name.runfiles to copy over
declare -rA RUNFILE_PATHS=(
  ["client/launcher/launcher_test"]="_main/client/test_data/launcher"
)

readonly SWARMING_TEST_DIR=${KOKORO_ARTIFACTS_DIR}/swarming_test
mkdir -p "${SWARMING_TEST_DIR}/tests"

# Copy into directory with same name as the test
for TEST_PATH in "${TESTS_LIST[@]}"; do
  TEST_NAME="$(basename -- "${TEST_PATH}")"
  TEST_DEST="${SWARMING_TEST_DIR}/tests/${TEST_NAME}/${TEST_NAME}"
  mkdir -p "${SWARMING_TEST_DIR}/tests/${TEST_NAME}"
  cp "bazel-bin/${TEST_PATH}" "${TEST_DEST}"

  if [[ -n "${RUNFILE_PATHS[${TEST_PATH}]}" ]]; then
    RUNFILE_PATH="${RUNFILE_PATHS[${TEST_PATH}]}"
    mkdir -p "${TEST_DEST}.runfiles/${RUNFILE_PATH}"
    # Copy files in path, resolving symlinks
    cp -rL "bazel-bin/${TEST_PATH}.runfiles/${RUNFILE_PATH}/." "${TEST_DEST}.runfiles/${RUNFILE_PATH}"
  fi
done

popd

###### Install and set up swarming/isolate

LUCI_ROOT="$(pwd)/luci"
export LUCI_ROOT
mkdir -p "${LUCI_ROOT}"

git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
PATH="$(pwd)/depot_tools:$PATH"
export PATH

# You can get valid git revision by looking up infra/tools/... at:
# https://chrome-infra-packages.appspot.com/
# These corresponds to git revision of the infra repo, where luci-go commits
# are regularly rolled out: https://chromium.googlesource.com/infra/infra
# Note that the '${platform}' must appear as-is in the ensure file,
# hence the single quotes.

#shellcheck disable=SC2016
(
  INFRA_GIT_REVISION=bcc65251593cabeccf4a36076dc2c5411c950a2e
  echo 'infra/tools/luci/isolate/${platform} git_revision:'"${INFRA_GIT_REVISION}"
  echo 'infra/tools/luci/swarming/${platform} git_revision:'"${INFRA_GIT_REVISION}"
) > "${LUCI_ROOT}/ensure_file.txt"
cipd ensure -ensure-file "${LUCI_ROOT}/ensure_file.txt" -root "${LUCI_ROOT}"

readonly KOKORO_KEY_NAME="78411_swarming-service-key"
readonly KOKORO_KEY_PATH="${KOKORO_KEYSTORE_DIR}/${KOKORO_KEY_NAME}"
export SWARMING_AUTH_FLAG="--service-account-json=${KOKORO_KEY_PATH}"

# Initialize some environment variables if unset
if [[ -z "${SWARMING_TIMESTAMP}" ]]; then
  SWARMING_TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
  export SWARMING_TIMESTAMP
fi

# Number that should be consistent for multiple runs of a PR
if [[ -z "${SWARMING_TASK_PREFIX}" ]]; then
  #shellcheck disable=SC2154
  export SWARMING_TASK_PREFIX="Kokoro_CI"
fi

###### Trigger (Upload and run)
# Records fails and continues to run, to collect results.

SWARMING_TRIGGER_ERROR=0

pushd "${SWARMING_TEST_DIR}"

for TEST_DIR in tests/*; do
  TEST_BINARY=$(basename -- "${TEST_DIR}")
  readonly TEST_BINARY
  readonly FULL_BINARY_PATH="${TEST_DIR}/${TEST_BINARY}"

  set +e
  "${HATS_SWARMING_DIR}/trigger.py" --prefix "${SWARMING_TASK_PREFIX}" "${TEST_DIR}" "${FULL_BINARY_PATH}"
  EXIT_CODE=$?
  set -e

  if [[ "${EXIT_CODE}" -ne 0 ]]; then
    echo "Swarming trigger error on test: ${TEST_NAME}" >&2
    SWARMING_TRIGGER_ERROR=1
  fi
done

popd

###### Collect results

pushd "${SWARMING_TEST_DIR}"

SWARMING_FAILURE=0
for TEST_NAME in triggered/*/*.json; do
  set +e
  "${HATS_SWARMING_DIR}/collect.py" "${SWARMING_TIMESTAMP}" "${KOKORO_GIT_COMMIT}" "$(basename -- "${TEST_NAME}" .json)" "${TEST_NAME}"
  EXIT_CODE=$?
  set -e

  if [[ "${EXIT_CODE}" -eq 0 ]]; then
    echo "PASS ${TEST_NAME}"
  else
    echo "FAIL ${TEST_NAME}"
    SWARMING_FAILURE=1
  fi
done

popd

### Exit 1 to make tests register as failed in Kokoro (-1)

if [[ "${SWARMING_FAILURE}" -eq 1 ]]; then
  echo "Error: some Swarming test failed" >&2
  exit 1
fi

if [[ "${SWARMING_TRIGGER_ERROR}" -eq 1 ]]; then
  echo "Error: could not trigger some Swarming tests" >&2
  exit 1
fi
