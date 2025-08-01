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

# This script is to build test binaries for swarming.
# The script is supposed to run in a Docker container.
set -euo pipefail
set -x

readonly KOKORO_HATS_DIR=/workspace

PREBUILT_DIR="$KOKORO_HATS_DIR/client/prebuilt"
mkdir -p "$PREBUILT_DIR"
source ./client/scripts/build-lib.sh
pushd client/scripts

#### Copy Oak binaries instead of building them to save time.
copy_oak_artifacts $PREBUILT_DIR

#### build the workload and bundle them together.
build_all_hats_containers_images "$PREBUILT_DIR"
build_test_application_container_bundle_tar "$PREBUILT_DIR"

readonly TEST_DATA_DIR="$KOKORO_HATS_DIR/client/trusted_application/test_data"
#### bundle everything nicely
build_test_bundles \
  "$TEST_DATA_DIR" \
  "$PREBUILT_DIR/stage0_bin" \
  "$PREBUILT_DIR/stage1.cpio" \
  "$PREBUILT_DIR/bzImage" \
  "$PREBUILT_DIR" \
  "$PREBUILT_DIR/bundle.tar" \
  "$KOKORO_HATS_DIR/client/trusted_application/configs/appraisal_policy.txtpb" \
  "$KOKORO_HATS_DIR/client/trusted_application/configs/launcher_config.txtpb"
popd

bazel build \
  --config=ci \
  --dynamic_mode=off \
  --verbose_failures=true \
  --build_tag_filters="virtualization" \
  --test_tag_filters="virtualization" \
  --compilation_mode=opt \
  //...

readonly TESTS_LIST=(
  "client/launcher/launcher_test"
  "client/trusted_application/integration_test/trusted_application_test"
)

#### Path within test_name.runfiles to copy over
declare -rA RUNFILE_PATHS=(
  ["client/launcher/launcher_test"]="_main/client/test_data/launcher"
  ["client/trusted_application/integration_test/trusted_application_test"]="_main/client/trusted_application/test_data"
)

readonly TEST_DIR="$KOKORO_HATS_DIR/binaries/tests"
mkdir -p "$TEST_DIR"

#### Copy into directory with same name as the test
for TEST_PATH in "${TESTS_LIST[@]}"; do
  TEST_NAME="$(basename -- "${TEST_PATH}")"
  TEST_DEST="${TEST_DIR}/${TEST_NAME}/${TEST_NAME}"
  mkdir -p "${TEST_DIR}/${TEST_NAME}"
  cp "bazel-bin/${TEST_PATH}" "${TEST_DEST}"

  if [[ -n "${RUNFILE_PATHS[${TEST_PATH}]}" ]]; then
    RUNFILE_PATH="${RUNFILE_PATHS[${TEST_PATH}]}"
    mkdir -p "${TEST_DEST}.runfiles/${RUNFILE_PATH}"
    # Copy files in path, resolving symlinks
    cp -rL "bazel-bin/${TEST_PATH}.runfiles/${RUNFILE_PATH}/." "${TEST_DEST}.runfiles/${RUNFILE_PATH}"
  fi
done
