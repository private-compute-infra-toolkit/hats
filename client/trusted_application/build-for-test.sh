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

set -e

TEST_APP_DIR="$(dirname "$0")"
readonly TEST_APP_DIR
PREBUILT_DIR="$(readlink -f "$TEST_APP_DIR/../prebuilt")"
TEST_DATA_DIR="$(readlink -f "$TEST_APP_DIR/test_data")"
readonly PREBUILT_DIR
cd "$TEST_APP_DIR"
mkdir -p "$PREBUILT_DIR"
git submodule update --init --recursive ../../submodules/oak ../../builders

# shellcheck disable=1091
source ../scripts/build-lib.sh

# build the workload and bundle them together.
build_oak_containers_stage0 "$PREBUILT_DIR"
build_oak_containers_stage1 "$PREBUILT_DIR"
build_oak_containers_kernel "$PREBUILT_DIR"
build_oak_containers_syslogd "$PREBUILT_DIR"
build_hats_containers_images "$PREBUILT_DIR" "test_single"
build_test_application_container_bundle_tar "$PREBUILT_DIR"


# bundle everything nicely
build_test_bundles \
  "$TEST_DATA_DIR" \
  "$PREBUILT_DIR/stage0_bin" \
  "$PREBUILT_DIR/stage1.cpio" \
  "$PREBUILT_DIR/bzImage" \
  "$PREBUILT_DIR/hats_system_image.tar.xz" \
  "$PREBUILT_DIR/bundle.tar" \
  "../trusted_application/test_data/appraisal_policy.txtpb" \
  "../trusted_application/test_data/launcher_config.txtpb"
