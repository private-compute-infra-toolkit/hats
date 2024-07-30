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

readonly SCRIPTS_DIR="$(dirname "$0")"
readonly PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"

# The oak_containers_launcher has hardcoded AMD SEV-SNP parameters
sudo ${PREBUILT_DIR}/launcher \
  --system-image ${PREBUILT_DIR}/image-old.tar.xz \
  --container-bundle ${PREBUILT_DIR}/oak_container_example_oci_filesystem_bundle.tar \
  --vmm-binary ${PREBUILT_DIR}/qemu-system-x86_64 \
  --stage0-binary ${PREBUILT_DIR}/stage0_bin \
  --kernel ${PREBUILT_DIR}/vanilla_bzImage \
  --initrd ${PREBUILT_DIR}/stage1.cpio \
  --memory-size="8G" \
  --ramdrive-size="10000000" \
  --vm-type sev-snp \
  --tvs-address $1 \
  --enable-parc \
  --parc-parameters-file ${PREBUILT_DIR}/parc_data/parameters/parameters-local.json \
  --parc-blobstore-root ${PREBUILT_DIR}/parc_data/blob_root
