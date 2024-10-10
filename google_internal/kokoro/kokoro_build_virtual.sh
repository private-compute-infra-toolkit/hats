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

### This version just for tests that require virtualization tools
# For example, /dev/kvm or /dev/vhost-vsock
# RBE is not supported for these, so they will be slower

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

KOKORO_HATS_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats"

# Apply patches
cd "${KOKORO_HATS_DIR}"
source "${KOKORO_HATS_DIR}/patches/apply_patches.sh"
patches::apply_common
patches::apply_python


cd "${KOKORO_HATS_DIR}/google_internal/kokoro"

args=(
  test
  --noshow_progress
  --verbose_failures=true
  --symlink_prefix=/
  # Only run KVM tests that rely on /dev/kvm, /dev/vhost-vsock, etc
  --test_tag_filters=virtualization
  --
  //...
)
./bazel_wrapper.py "${args[@]}"
