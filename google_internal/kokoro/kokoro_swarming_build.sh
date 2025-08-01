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
set -euo pipefail

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
# export TZ=Etc/UTC
# export PS4='+\t $(basename -- ${BASH_SOURCE[0]}):${LINENO} ' # xtrace prompt
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

pushd "${KOKORO_HATS_DIR}"

##### Launch Docker to build the test binaries.
docker_run_flags=(
  '--rm'
  '--workdir=/workspace'
  '--network=host'
  '--security-opt=seccomp=unconfined'
  # BIND MOUNTS - Make host directories available in container.
  "--mount=type=bind,source=$KOKORO_HATS_DIR,target=/workspace"
  # This prevent bazel from having to re-populate the cache every time you start
  # your local docker container.
  '--mount=type=volume,src=bazel-cache,target=/root/.cache/bazel'
)

DOCKER_IMAGE_ID="us-central1-docker.pkg.dev/ps-hats-playground/presubmit/presubmit@sha256:2249f8185aa452c63ad76f0721c10f7ddff8bc26b4e0a36f8e682f264b3f1057"

docker run "${docker_run_flags[@]}" $DOCKER_IMAGE_ID ./google_internal/kokoro/build_test.sh

##### Copy binaries to directory

readonly SWARMING_TEST_DIR=${KOKORO_ARTIFACTS_DIR}/swarming_test
rsync -rvaz ./binaries/tests  "${SWARMING_TEST_DIR}/"

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
if [[ -z "${SWARMING_TIMESTAMP:-}" ]]; then
  SWARMING_TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
  export SWARMING_TIMESTAMP
fi

# Number that should be consistent for multiple runs of a PR
if [[ -z "${SWARMING_TASK_PREFIX:-}" ]]; then
  #shellcheck disable=SC2154
  export SWARMING_TASK_PREFIX="Kokoro_PR_${KOKORO_GERRIT_CHANGE_NUMBER}"
fi

###### Trigger (Upload and run)
# Records fails and continues to run, to collect results.

SWARMING_TRIGGER_ERROR=0

pushd "${SWARMING_TEST_DIR}"

for TEST_DIR in tests/*; do
  TEST_BINARY=$(basename -- "${TEST_DIR}")
  FULL_BINARY_PATH="${TEST_DIR}/${TEST_BINARY}"

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
# Which depends on scm config, support both
readonly COMMIT_HASH=${KOKORO_GIT_COMMIT:-KOKORO_GIT_COMMIT_hats}
for TEST_NAME in triggered/*/*.json; do
  set +e
  "${HATS_SWARMING_DIR}/collect.py" "${SWARMING_TIMESTAMP}" "${COMMIT_HASH}" "$(basename -- "${TEST_NAME}" .json)" "${TEST_NAME}"
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
