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

set -e

function build_oak_stage0() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK STAGE0..."
  pushd ../../submodules/oak/
  nix develop --command just stage0_bin && \
    rsync artifacts/stage0_bin "$BUILD_DIR"
  popd
}

function build_oak_restricted_kernel() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK RESTRICTED KERNEL..."
  pushd ../../submodules/oak/
  nix develop --command just oak_restricted_kernel_wrapper_virtio_console_channel && \
    rsync oak_restricted_kernel_wrapper/bin/wrapper_bzimage_virtio_console_channel "$BUILD_DIR"
  popd
}

function build_oak_orchestrator() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK ORCHESTRATOR..."
  pushd ../../submodules/oak/
  nix develop --command just build_oak_orchestrator && \
    rsync artifacts/enclave_apps/oak_orchestrator "$BUILD_DIR"
  popd
}

function build_tvs_enclave_app() {
  local BUILD_DIR="$1"
  printf "\nBUILDING TVS ENCLAVE APP..."
  pushd ../../
  bazel build -c opt //tvs/trusted_tvs/enclave_app:enclave_main && \
    rsync bazel-bin/tvs/trusted_tvs/enclave_app/enclave_main "$BUILD_DIR"
  popd
}

function build_untrusted_tvs() {
  local BUILD_DIR="$1"
  printf "\nBUILDING UNTRUSTED TVS..."
  pushd ../../
  bazel build -c opt //tvs/untrusted_tvs:tvs-server_main && \
    rsync bazel-bin/tvs/untrusted_tvs/tvs-server_main "$BUILD_DIR"
  popd
}
CUR_DIR="$(dirname "$0")"
readonly CUR_DIR
PREBUILT_DIR="$(readlink -f "$CUR_DIR/prebuilt")"
readonly PREBUILT_DIR
cd "$CUR_DIR"
mkdir -p "$PREBUILT_DIR"
git submodule update --init --recursive

build_oak_stage0 "$PREBUILT_DIR"
build_oak_restricted_kernel "$PREBUILT_DIR"
build_oak_orchestrator "$PREBUILT_DIR"
build_tvs_enclave_app "$PREBUILT_DIR"
build_untrusted_tvs "$PREBUILT_DIR"
