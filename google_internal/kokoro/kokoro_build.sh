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

KOKORO_HATS_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats"

# In Kokoro, git meta files are stripped off. pre-commit only runs in
# directories. We run this before patching to workspace as the patches
# might leave files in a format that pre-commit does not like.
git config --global --add safe.directory "${KOKORO_HATS_DIR}"
cd "${KOKORO_HATS_DIR}"
# Run pre-commit hooks.
pre-commit run -a

# Apply patches
cd "${KOKORO_HATS_DIR}"
source "${KOKORO_HATS_DIR}/patches/apply_patches.sh"
patches::apply_common
patches::apply_python


cd "${KOKORO_HATS_DIR}/google_internal/kokoro"

#shellcheck disable=SC1091
source "${KOKORO_HATS_DIR}/google_internal/lib_build.sh"

lib_build::configure_gcloud_access
lib_build::set_rbe_flags

# Skip builds/tests that fail on Kokoro
# nopresubmit: general tests that Kokoro can't run
# virtualization: builds/tests that require virtualization, such as
#    /dev/kvm, /dev/vhost-vsock, etc.
tag_filters="-nopresubmit,-virtualization"

args=(
  "${BAZEL_STARTUP_ARGS_ABSL}"
  test
  # "${BAZEL_DIRECT_ARGS}"
  # Multiple args in one strings breaks, due to py wrapper
  --config=rbecache
  --config=kokoro
  --google_default_credentials
  --noshow_progress
  --verbose_failures=true
  --symlink_prefix=/
  --build_tag_filters="${tag_filters}"
  --test_tag_filters="${tag_filters}"
  --
  //...
)
./bazel_wrapper.py "${args[@]}"
