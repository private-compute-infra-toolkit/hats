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


KOKORO_HATS_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats"

# In Kokoro, git meta files are stripped off. pre-commit only runs in
# directories. We run this before patching to workspace as the patches
# might leave files in a format that pre-commit does not like.
git config --global --add safe.directory "${KOKORO_HATS_DIR}"
cd "${KOKORO_HATS_DIR}"


###### Check 1: Pre-commit

pre-commit run -a

###### Check 2: Bazel test -nopresubmit

# Apply patches
cd "${KOKORO_HATS_DIR}"
source "${KOKORO_HATS_DIR}/patches/apply_patches.sh"
patches::apply_python

cd "${KOKORO_HATS_DIR}/google_internal/kokoro"

#shellcheck disable=SC1091
source "${KOKORO_HATS_DIR}/google_internal/lib_build.sh"

lib_build::configure_gcloud_access
lib_build::set_rbe_flags

# Given as space delimited string, which is for builders lib
# This converts them to array, so bash parses them as multiple arguments
IFS=" " read -r -a BAZEL_DIRECT_ARGS <<< "$BAZEL_DIRECT_ARGS"

# Skip builds/tests that fail on Kokoro
# nopresubmit: general tests that Kokoro can't run
# virtualization: builds/tests that require virtualization, such as
#    /dev/kvm, /dev/vhost-vsock, etc.
tag_filters="-nopresubmit,-virtualization"

args=(
  "${BAZEL_STARTUP_ARGS_ABSL}"
  test
  "${BAZEL_DIRECT_ARGS[@]}"
  --config=ci
  --verbose_failures=true
  --experimental_convenience_symlinks=ignore
  --build_tag_filters="${tag_filters}"
  --test_tag_filters="${tag_filters}"
  --
  //...
)
./bazel_wrapper.py "${args[@]}"

###### Check 3: Binary hashes

git config --global --add safe.directory "${KOKORO_HATS_DIR}/submodules/oak"
git config --global --add safe.directory "${KOKORO_HATS_DIR}/.git/modules/oak"

pushd "${KOKORO_HATS_DIR}"

pushd client/scripts
source ./build-lib.sh

if check_oak_artifacts; then
  echo "found up to date oak artifacts"
else
  echo "Oak artifacts are missing or out of date."
  echo "Exiting to not build oak"
  exit 1
fi

# Same directory used by check/update hashes
PREBUILT_DIR="${KOKORO_HATS_DIR}/client/prebuilt"
mkdir -p "$PREBUILT_DIR"
copy_oak_artifacts "$PREBUILT_DIR"
popd

readonly RUNTIME_HASH_FILE="client/trusted_application/enclave_app/SHA256SUMS"
readonly SYSTEM_IMAGE_HASH_FILE="client/system_image/SHA256SUMS"
FAILURE=0

# Save previous hashes
OLD_RUNTIME_HASH="$(sort "${RUNTIME_HASH_FILE}")"
OLD_IMAGE_HASHES="$(sort "${SYSTEM_IMAGE_HASH_FILE}")"
# Update hashes
./client/scripts/update-hashes.sh
# Compare sorted, to see if changed
# Still continue on new hashes, to see if policies also need updating.
if [[ "${OLD_RUNTIME_HASH}" != "$(sort "${RUNTIME_HASH_FILE}")" ]]; then
  echo "Error: Runtime hash changed. Use ./client/scripts/update_hashes.sh"
  FAILURE=1
fi
if [[ "${OLD_IMAGE_HASHES}" != "$(sort "${SYSTEM_IMAGE_HASH_FILE}")" ]]; then
  echo "Error: System image hashes changed. Use ./client/scripts/update_hashes.sh"
  FAILURE=1
fi
# Check policies
./client/scripts/check-hashes.sh || FAILURE=1

if [[ "${FAILURE}" -eq 1 ]]; then
  echo "Error: some hashes need updating. "\
       "Use ./client/scripts/update_hashes.sh followed by ./client/scripts/check_hashes.sh"
  exit 1
fi

popd
