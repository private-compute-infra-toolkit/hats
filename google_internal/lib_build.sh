#!/bin/bash
# Based on Kiwi KV's lib_build

#######################################
# Configure and export the WORKSPACE variable in kokoro
# If set, skips
# If Kokoro, uses that specific path
# If not set, use top level
#######################################
function lib_build::set_workspace() {
  export WORKSPACE
  if [[ -v WORKSPACE ]]; then
    return
  fi
  if [[ -n ${KOKORO_ARTIFACTS_DIR} ]]; then
    # NOTE: Update path as needed
    WORKSPACE="${KOKORO_ARTIFACTS_DIR}/git/hats"
  elif [[ -z ${WORKSPACE} ]]; then
    WORKSPACE="$(git rev-parse --show-toplevel)"
  fi
}

#######################################
# Check that gcloud information is properly set up
#
# Set account if not Kokoro
# In the future, also check artifact registry permission once those are being used
#######################################
function lib_build::configure_gcloud_access() {
  declare -r GAR_HOST=us-docker.pkg.dev
  declare -r GAR_PROJECT=kiwi-air-force-remote-build
  declare -r GAR_REPO="${GAR_HOST}/${GAR_PROJECT}/privacysandbox/builders"

  # Set account if no Kokoro artifact dir (i.e. not kokoro)
  if [[ -z ${KOKORO_ARTIFACTS_DIR} ]]; then
    declare -r _ACCOUNT="${USER}@google.com"
    if [[ $(gcloud config get account) != "${_ACCOUNT}" ]]; then
      printf "Error. Set default gcloud account using \`gcloud config set account %s\`\n" "${_ACCOUNT}" &>/dev/stderr
      return 1
    fi
    if [[ $(gcloud config get project) != "${GAR_PROJECT}" ]]; then
      printf "Error. Set default gcloud project using \`gcloud config set project %s\`\n" "${GAR_PROJECT}" &>/dev/stderr
      return 1
    fi
  fi
}

#######################################
# Set up bazel flags for use with RBE
#
# Optionally also set credentials
#######################################
function lib_build::set_rbe_flags() {
  lib_build::set_workspace

  export BAZEL_STARTUP_ARGS="--bazelrc=${WORKSPACE}/google_internal/.bazelrc"
  declare -a _BAZEL_ARGS=(
    "--config=rbecache"
  )

  export BAZEL_DIRECT_ARGS="${_BAZEL_ARGS[*]} --google_default_credentials"
  # optionally set credentials (likely useful only if executing this outside kokoro)
  declare -r HOST_CREDS_JSON="${HOME}/.config/gcloud/application_default_credentials.json"
  if [[ -s ${HOST_CREDS_JSON} ]]; then
    declare -r CREDS_JSON=/gcloud/application_default_credentials.json
    export BAZEL_EXTRA_ARGS="${_BAZEL_ARGS[*]} --google_credentials=${CREDS_JSON}"
  else
    export BAZEL_EXTRA_ARGS="${BAZEL_DIRECT_ARGS}"
  fi
}
