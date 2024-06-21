#!/bin/bash

# Fail on any error.
set -e

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
set -x

echo "Starting kokoro_build"

BAZEL_VERSION=bazel-7.2.0-linux-x86_64
BAZEL_TMP_DIR=/tmpfs/tmp/bazel-release
mkdir -p "${BAZEL_TMP_DIR}"
echo "Bazel file: ${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
ls "${KOKORO_GFILE_DIR}"
ln -fs "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}" "${BAZEL_TMP_DIR}/bazel"
chmod 755 "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
export PATH="${BAZEL_TMP_DIR}:${PATH}"
# This should show /tmpfs/tmp/bazel-release/bazel
which bazel
KOKORO_LOCAL_DIR="${KOKORO_ARTIFACTS_DIR}/git/hats/kokoro"

# Cd required to be in workspace
cd "${KOKORO_LOCAL_DIR}"
args=(
  test
  --verbose_failures=true
  # --test_output=all
  --symlink_prefix=/
  --
  //...
)
./bazel_wrapper.py "${args[@]}"
