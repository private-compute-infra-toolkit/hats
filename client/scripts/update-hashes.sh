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

###### Compute hashes and store them in hash files

set -euo pipefail

TEST_APP_DIR="$(dirname "$0")"
readonly TEST_APP_DIR
PREBUILT_DIR="$(readlink -f "$TEST_APP_DIR/../prebuilt")"
readonly PREBUILT_DIR
mkdir -p "$PREBUILT_DIR"
CLIENT_DIR="$(dirname "$(readlink -fm "${TEST_APP_DIR}")")"
readonly CLIENT_DIR
cd "$TEST_APP_DIR"

# Files
readonly RUNTIME_HASH_FILE="${CLIENT_DIR}/trusted_application/enclave_app/SHA256SUMS"
readonly SYSTEM_IMAGE_HASH_FILE="${CLIENT_DIR}/system_image/SHA256SUMS"

source ../scripts/build-lib.sh

#### Group 1: Container binary: Runtime
build_test_application_container_bundle_tar "$PREBUILT_DIR"
RUNTIME_HASH=$(sha256sum "${PREBUILT_DIR}/bundle.tar" | cut -d " " -f 1)
echo "Runtime hash: ${RUNTIME_HASH}"

# Update hash file
touch "${RUNTIME_HASH_FILE}"
sed -i '/container_binary$/d' "${RUNTIME_HASH_FILE}"
echo "${RUNTIME_HASH} container_binary" >> "${RUNTIME_HASH_FILE}"

#### Group 2: Various system images

build_all_hats_containers_images "$PREBUILT_DIR"

# Get suffixes of images from $PREBUILT_DIR.
mapfile -t IMAGE_SUFFIXES < <(find "${PREBUILT_DIR}" -name "hats_system_image_*" | sed -rn 's/.*hats_system_image_(.*).tar.xz/\1/p')

# Compute hashes
IMAGE_HASHES=()
for SUFFIX in "${IMAGE_SUFFIXES[@]}"; do
  echo "computing system image for ${SUFFIX}"
  HASH=$(sha256sum "${PREBUILT_DIR}/hats_system_image_$SUFFIX.tar.xz" | cut -d " " -f 1)
  echo "System hash for ${SUFFIX}: ${HASH}"
  IMAGE_HASHES+=("${HASH}")
done

# Update hash file
touch "${SYSTEM_IMAGE_HASH_FILE}"
sed -i '/hats_system_image_/d' "${SYSTEM_IMAGE_HASH_FILE}"

for index in "${!IMAGE_SUFFIXES[@]}"; do
  echo "${IMAGE_HASHES[$index]} hats_system_image_${IMAGE_SUFFIXES[$index]}" >> "${SYSTEM_IMAGE_HASH_FILE}"
done
