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

BAZEL_VERSION=bazel-7.2.0-linux-x86_64
BAZEL_TMP_DIR=/tmpfs/tmp/bazel-release
mkdir -p "${BAZEL_TMP_DIR}"
echo "Bazel file: ${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
ln -fs "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}" "${BAZEL_TMP_DIR}/bazel"
chmod 755 "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
export PATH="${BAZEL_TMP_DIR}:${PATH}"
# This should show /tmpfs/tmp/bazel-release/bazel
which bazel

KOKORO_HATS_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats"

# Apply patch
cd "${KOKORO_HATS_DIR}/submodules/common"
git apply ../../patches/parc/parc.patch

# Patch WORKSPACE to use `google_privacysandbox_servers_common` from a local path.
cd "${KOKORO_HATS_DIR}"
perl -i -pe 'BEGIN{undef $/;} s/git_repository\(\n[\s\t]*name = \"google_privacysandbox_servers_common\",\n[\s\t]*commit = \"[^\"]+\",\n([\s\t]*patches = \[\n([\s\t]*\"[^\"]+\",)+\n[\s\t]*\],)\n[\s\t]*remote = \"sso[^\"]+\",\n\)/local_repository\(\n\tname = \"google_privacysandbox_servers_common\",\n\tpath = \"submodules\/common"\n)/smg' WORKSPACE

cd "${KOKORO_HATS_DIR}/google_internal/kokoro"

#shellcheck disable=SC1091
source "${KOKORO_HATS_DIR}/google_internal/lib_build.sh"

lib_build::configure_gcloud_access
lib_build::set_rbe_flags

args=(
  "${BAZEL_STARTUP_ARGS_ABSL}"
  test
  # "${BAZEL_DIRECT_ARGS}"
  # Multiple args in one strings breaks, due to py wrapper
  --config=rbecache
  --google_default_credentials
  --noshow_progress
  --verbose_failures=true
  --symlink_prefix=/
    # presubmit server complains as `tar_pkg` rules runs python
    # and the presubmit runs as root. So here we exclude these
    # rules that we tagged them with *nopresubmit*.
    # https://screenshot.googleplex.com/3ThEtDfNQTE3YW4
  --build_tag_filters=-nopresubmit
  # presubmit server cannot bind to a port in kokoro environment
  # and so we exclude those tests with *nopresubmit*.
  # https://screenshot.googleplex.com/BXzFU3LAVqcTmTP
  --test_tag_filters=-nopresubmit
  --
  //...
)
./bazel_wrapper.py "${args[@]}"
