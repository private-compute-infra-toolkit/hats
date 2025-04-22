#!/bin/bash
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
  # declare -r GAR_HOST=us-docker.pkg.dev
  declare -r GAR_PROJECT=kiwi-air-force-remote-build
  # declare -r GAR_REPO="${GAR_HOST}/${GAR_PROJECT}/privacysandbox/builders"

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

  # Relative, for bazel_debian
  export BAZEL_STARTUP_ARGS="--bazelrc=google_internal/.bazelrc"
  # Absl for bazel_rbe to run in any sub-folder
  export BAZEL_STARTUP_ARGS_ABSL="--bazelrc=${WORKSPACE}/google_internal/.bazelrc"
  declare -a _BAZEL_ARGS=(
    "--config=rbecache"
  )

  # Env vars can't be arrays, so use space-delimited string instead
  export BAZEL_DIRECT_ARGS="${_BAZEL_ARGS[*]} --google_default_credentials"
  declare -a DOCKER_RUN_ARGS
  # optionally set credentials (likely useful only if executing this outside kokoro)
  declare -r HOST_CREDS_JSON="${HOME}/.config/gcloud/application_default_credentials.json"
  if [[ -s ${HOST_CREDS_JSON} ]]; then
    declare -r CREDS_JSON=/gcloud/application_default_credentials.json
    export BAZEL_EXTRA_ARGS="${_BAZEL_ARGS[*]} --google_credentials=${CREDS_JSON}"
    DOCKER_RUN_ARGS+=(
      "--volume ${HOST_CREDS_JSON}:${CREDS_JSON}"
    )
  else
    export BAZEL_EXTRA_ARGS="${BAZEL_DIRECT_ARGS}"
  fi
  export EXTRA_DOCKER_RUN_ARGS="${DOCKER_RUN_ARGS[*]}"
}

#######################################
# Set up bazel flags for use with RBE
#
# Optionally also set credentials
#######################################
function lib_build::get_docker_images() {
  lib_build::set_workspace
  lib_build::configure_gcloud_access

  if [[ -n $1 ]]; then
    declare -n _image_list=$1
  else
    declare -a -r _image_list=(
      presubmit
      build-debian
      # build-amazonlinux2
      # utils
      # test-tools
    )
  fi

  declare -r GAR_HOST=us-docker.pkg.dev
  declare -r GAR_PROJECT=kiwi-air-force-remote-build
  declare -r GAR_REPO="${GAR_HOST}/${GAR_PROJECT}/privacysandbox/builders"

  # update gcloud if it doesn't support artifact registry
  if ! gcloud artifacts --help &>/dev/null; then
    yes | gcloud components update
  fi

  # update docker config to use gcloud for auth to required artifact registry repo
  if ! yes | gcloud auth configure-docker ${GAR_HOST} >/dev/null; then
    printf "Error configuring docker for Artifact Registry [%s]\n" "${GAR_HOST}" &>/dev/stderr
    return 1
  fi

  # test connecting to GAR repo
  if ! gcloud artifacts docker images list "${GAR_REPO}/build-debian" --include-tags --limit 1 >/dev/null; then
    printf "Error connecting to Artifact Registry [%s]\n" "${GAR_REPO}" &>/dev/stderr
    return 1
  fi

  for IMAGE in "${_image_list[@]}"; do
    printf "Pulling or generating image [%s]\n" "${IMAGE}"
    if ! "${WORKSPACE}"/google_internal/pull_builder_image --image "${IMAGE}"; then
      printf "Error pulling, regenerating or pushing image [%s]\n" "${IMAGE}" &>/dev/stderr
      return 1
    fi
  done
}
