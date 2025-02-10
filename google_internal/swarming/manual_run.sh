#!/bin/bash
# Copyright 2025 Google LLC
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

set -e

export TZ=Etc/UTC
export PS4='+\t $(basename ${BASH_SOURCE[0]}):${LINENO} ' # xtrace prompt
set -x

# This can be run from any dir, but is recommended to be in swarming/
# Note: This builds support files (digest, isolate, summary, triggered) in
# the directory that the scrip twas executed in.
# Therefore it is recommended to run it in swarming/ for the .gitignore to
# cover these files
SCRIPT_DIR=$(dirname -- "${BASH_SOURCE[0]}")
readonly SCRIPT_DIR

SWARMING_TEST_SCRIPT=$1
SWARMING_TEST_DIR=$(dirname -- "${SWARMING_TEST_SCRIPT}")
if [[ -z "${SWARMING_TEST_SCRIPT}" ]] || [[ ! -f "${SWARMING_TEST_SCRIPT}" ]]; then
  echo "Error: missing or invalid test executable argument"
  echo "Usage: $(basename -- "$0") tests/foobar/test_executable"
  echo "This uses tests/foobar as the test directory containing all files"
  exit 1
fi

# Fake Swarming environment
SWARMING_TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
export SWARMING_TIMESTAMP
export SWARMING_TASK_PREFIX="Manual"
# No service account, run as user
export SWARMING_AUTH_FLAG=""

# Remove results of previous manual run, includes summary/results
rm -rf triggered/

"${SCRIPT_DIR}/trigger.py" --prefix "${SWARMING_TASK_PREFIX}" "${SWARMING_TEST_DIR}" "${SWARMING_TEST_SCRIPT}"

ls triggered/*

# Allow non-zero return values during collection
for TEST_NAME in triggered/*/*.json; do
  echo "Collecting for test name: ${TEST_NAME}"
  set +e
  "${SCRIPT_DIR}/collect.py" "${SWARMING_TIMESTAMP}" "manual" "$(basename -- "${TEST_NAME}" .json)" "${TEST_NAME}" --results_json=triggered/results.json
  EXIT_CODE=$?
  set -e
  if [ ${EXIT_CODE} -eq 0 ]; then
    echo "PASS ${TEST_NAME}"
  else
    echo "FAIL ${TEST_NAME}"
  fi
done
