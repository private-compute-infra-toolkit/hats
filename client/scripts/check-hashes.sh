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

###### Check appraisal policy hashes against hash files

set -e
set -o pipefail

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

POLICIES=(
  "${CLIENT_DIR}/trusted_application/configs/appraisal_policy.txtpb"
  "${CLIENT_DIR}/trusted_application/configs/appraisal_policy_insecure.txtpb"
)

# Read saved hashes
if [[ ! -f "$RUNTIME_HASH_FILE" ]]; then
  echo "Error: Runtime hash file missing"
  exit 1
fi
while read -r line; do
  HASH=${line% *}
  NAME=${line#* }
  if [[ "$NAME" == "container_binary" ]]; then
    RUNTIME_HASH="$HASH"
  fi
done < "$RUNTIME_HASH_FILE"
if [[ -z $RUNTIME_HASH ]]; then
  echo "Error: No container binary hash found."
  exit 1
fi

IMAGE_HASHES=()
if [[ ! -f "$SYSTEM_IMAGE_HASH_FILE" ]]; then
  echo "Error: System image hash file missing"
  exit 1
fi
while read -r line; do
  HASH=${line% *}
  NAME=${line#* }
  if [[ "$NAME" =~ "hats_system_image_" ]]; then
    IMAGE_HASHES+=("$HASH")
  fi
done < "$SYSTEM_IMAGE_HASH_FILE"
if ! (( ${#IMAGE_HASHES[@]} )); then
  echo "Error: No hats system image hashes found."
  exit 1
fi

# Check policies
FAILURE=0

for POLICY_FILE in "${POLICIES[@]}"; do
  FOUND_IMAGES=$(grep "system_image_sha256" "${POLICY_FILE}" | cut -d ":" -f 2 | tr -cd "0-9a-f\n")
  for hash in ${FOUND_IMAGES//\\n/ }; do
    if ! printf '%s\n' "${IMAGE_HASHES[@]}" | grep -Fx -- "${hash}" > /dev/null; then
      # Grep can't find exact line match
      echo "Unknown system image hash in ${POLICY_FILE}: ${hash}"
      FAILURE=1
    fi
  done

  FOUND_BINARY=$(grep "container_binary_sha256" "${POLICY_FILE}" | cut -d ":" -f 2 | tr -cd "0-9a-f\n")

  for hash in ${FOUND_BINARY//\\n/ }; do
    if [[ "${hash}" != "${RUNTIME_HASH}" ]]; then
      echo "Unknown container binary hash in ${POLICY_FILE}: ${hash}"
      FAILURE=1
    fi
  done
done

if [[ "${FAILURE}" -eq 1 ]]; then
  echo "Error: some hashes need updating"
  exit 1
fi

echo "Appraisal policy hashes for binaries are up to date"
