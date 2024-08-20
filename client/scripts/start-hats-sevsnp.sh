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

# The oak_containers_launcher has hardcoded AMD SEV-SNP parameters
# Note: --tvs-authentication-key is a test key.
sudo "${PREBUILT_DIR}/launcher" \
  --system-image "${PREBUILT_DIR}/hats_system_image.tar.xz" \
  --container-bundle "${PREBUILT_DIR}/oak_container_example_oci_filesystem_bundle.tar" \
  --vmm-binary "${PREBUILT_DIR}/qemu-system-x86_64" \
  --stage0-binary "${PREBUILT_DIR}/stage0_bin" \
  --kernel "${PREBUILT_DIR}/vanilla_bzImage" \
  --initrd "${PREBUILT_DIR}/stage1.cpio" \
  --memory-size="8G" \
  --ramdrive-size="10000000" \
  --vm-type sev-snp \
  --tvs-address "$1" \
  --tvs-authentication-key=f1af8f26497c24e3944709baccd6b6f4c9326fd902317189f4b2c4adfe2e6af9
