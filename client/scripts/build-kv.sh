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

SCRIPTS_DIR="$(dirname "$0")"
readonly SCRIPTS_DIR
PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"
readonly PREBUILT_DIR
cd "$SCRIPTS_DIR"
mkdir -p "$PREBUILT_DIR"
git submodule update --init --recursive

# shellcheck disable=1091
source ./build-lib.sh

# build launcher / local TVS server / KeyGen
build_hats_launcher "$PREBUILT_DIR"
build_tvs "$PREBUILT_DIR"
build_test_keygen "$PREBUILT_DIR"

# build the workload and bundle them together.
build_oak_containers_stage0 "$PREBUILT_DIR"
build_oak_containers_stage1 "$PREBUILT_DIR"
build_oak_containers_kernel "$PREBUILT_DIR"
build_oak_containers_syslogd "$PREBUILT_DIR"
build_hats_containers_images "$PREBUILT_DIR"
build_kv_bundle "$PREBUILT_DIR"

# bundle everything nicely
build_launch_bundle \
  "$PREBUILT_DIR" \
  "$PREBUILT_DIR/stage0_bin" \
  "$PREBUILT_DIR/stage1.cpio" \
  "$PREBUILT_DIR/bzImage" \
  "$PREBUILT_DIR/hats_system_image.tar.xz" \
  "$PREBUILT_DIR/kv-bundle.tar" \
  "../../tvs/appraisal_policies/kv.textproto" \
  "./launcher_configs/kv_launcher_config.textproto"
