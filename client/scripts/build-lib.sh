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

function build_kv_bundle() {
  local BUILD_DIR="$1"
  printf "\nBUILDING KV SERVICE..."
  pushd ../../submodules/kv-server
  # kv-server has submodules that we need to pull newer commits manually.
  pushd common
  git checkout ca6f05ec8af424f55eb7a67811077b650c6d295c
  popd
  ./builders/tools/bazel-debian build \
    //production/packaging/hats/data_server:kv-bundle \
    --config=local_instance \
    --config=local_platform \
    --config=enable_parc \
    --config=enable_hats
  rsync bazel-bin/production/packaging/hats/data_server/kv-bundle.tar "$BUILD_DIR"
  popd
}

function build_oak_containers_kernel() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS KERNEL..."
  pushd ../../submodules/oak/
  nix develop --command just oak_containers_kernel && \
    rsync ./oak_containers/kernel/target/bzImage "$BUILD_DIR"
  popd
}

function build_oak_containers_images() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS IMAGES..."
  pushd ../../submodules/oak/oak_containers_system_image
  nix develop --command ./build-old.sh && \
    rsync target/output.img "$BUILD_DIR" && \
    rsync target/image-old.tar "$BUILD_DIR" && \
    xz --force "$BUILD_DIR/image-old.tar"
  popd
}

function build_oak_containers_launcher() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS LAUNCHER..."
  pushd ../../submodules/oak
  nix develop --command just oak_containers_launcher && \
    rsync ./target/x86_64-unknown-linux-gnu/release/oak_containers_launcher "$BUILD_DIR"
  popd
}

function build_oak_containers_stage0() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS STAGE0..."
  pushd ../../submodules/oak
  nix develop --command just stage0_bin && \
    rsync ./generated/stage0_bin "$BUILD_DIR"
  popd
}

function build_oak_containers_stage1() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS STAGE1..."
  pushd ../../submodules/oak
  nix develop --command just stage1_cpio && \
    rsync ./target/stage1.cpio "$BUILD_DIR"
  popd
}

function build_oak_hello_world_container_bundle_tar() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK HELLO WORLD CONTAINER BUNDLE TAR..."
  pushd ../../submodules/oak
  # just command to build the container tries to copy a file to
  # a folder it doesn't have permission to do so and it fails at that
  # step; so here we copy after we call `just`.
  nix develop --command  bazel build --compilation_mode opt //oak_containers/examples/hello_world/trusted_app:bundle.tar && \
    rsync ./bazel-bin/oak_containers/examples/hello_world/trusted_app/bundle.tar "$BUILD_DIR/oak_container_example_oci_filesystem_bundle.tar"

  popd
}

function build_test_application_container_bundle_tar() {
  local BUILD_DIR="$1"
  printf "\nBUILDING TEST APPLICATION CONTAINER BUNDLE TAR..."
  bazel build -c opt //client/trusted_application:bundle
  cp -f ../../bazel-bin/client/trusted_application/bundle.tar "$BUILD_DIR"
}

function build_test_main() {
  local BUILD_DIR="$1"
  printf "\nBUILDING TEST MAIN..."
  bazel build -c opt //client/trusted_application:test_main
  cp -f ../../bazel-bin/client/trusted_application/test_main "$BUILD_DIR"
}

function build_snphost() {
  local BUILD_DIR="$1"
  pushd ../../submodules/oak
  nix develop --command cargo install --root "$BUILD_DIR" snphost && \
    mv "$BUILD_DIR"/bin/snphost "$BUILD_DIR" && \
    rmdir "$BUILD_DIR/bin"
  popd
}

function build_hats_launcher() {
  local BUILD_DIR="$1"
  echo "BUILDING LAUNCHER CC"
  bazel build -c opt //client/launcher:launcher_main
  cp -f ../../bazel-bin/client/launcher/launcher_main "$BUILD_DIR"
  cp -r ../test_data/parc_data "$BUILD_DIR"
}

function build_oak_containers_syslogd() {
  local BUILD_DIR="$1"
  cat << EOF > "$BUILD_DIR/BUILD"
exports_files([
  "oak_containers_syslogd",
])
EOF
  printf "\nBUILDING OAK CONTAINERS SYSLOGD"
  pushd ../../submodules/oak
  nix develop --command bazel build -c opt //oak_containers/syslogd:oak_containers_syslogd && \
    cp -f bazel-bin/oak_containers/syslogd/oak_containers_syslogd "$BUILD_DIR/oak_containers_syslogd"
  popd
}

function build_hats_containers_images() {
  local BUILD_DIR="$1"
  bazel build -c opt //client/system_image:hats_system_image --//:syslogd_source=binary
  cp -f ../../bazel-bin/client/system_image/hats_system_image.tar "$BUILD_DIR"
  xz --force "$BUILD_DIR/hats_system_image.tar"
}

function build_tvs() {
  local BUILD_DIR="$1"
  bazel build -c opt //tvs/untrusted_tvs:tvs-server_main
  cp -f ../../bazel-bin/tvs/untrusted_tvs/tvs-server_main "$BUILD_DIR"
}

function build_test_keygen() {
  local BUILD_DIR="$1"
  bazel build -c opt //key_manager:key-gen
  cp -f ../../bazel-bin/key_manager/key-gen "$BUILD_DIR"
}

# A tar file contains all launch required data.
# A textproto file contains all launch parameters.
# Secrets are in parameters only.
function build_launch_bundle() {
  echo "Building Launcher Bundle"
  local BUILD_DIR="$1"
  local STAGE0="$2"
  local INITRD="$3"
  local KERNEL="$4"
  local SYSTEM="$5"
  local RUNTIME="$6"
  local APPRISAL_POLICY="$7"
  local LAUNCHER_CONFIG="$8"
  local TAR_DIR="$BUILD_DIR/tar"
  mkdir -p "$TAR_DIR"
  mv -f "$STAGE0" "$TAR_DIR/stage0_bin"
  mv -f "$INITRD" "$TAR_DIR/initrd.cpio.xz"
  mv -f "$KERNEL" "$TAR_DIR/kernel_bin"
  mv -f "$SYSTEM" "$TAR_DIR/system.tar.xz"
  tar -C "$TAR_DIR" -cf "$BUILD_DIR/system_bundle.tar" .
  mv -f "$RUNTIME" "$BUILD_DIR/runtime_bundle.tar"
  cp "$LAUNCHER_CONFIG" "$BUILD_DIR/launcher_config.prototext"
  cp "$APPRISAL_POLICY" "$BUILD_DIR/appraisal_policy.prototext"
  # Init script to generate fake test keys.
  cp "../scripts/keygen-local-init.sh" "$BUILD_DIR/"
  cp "../scripts/launcher-up.sh" "$BUILD_DIR/"
  cp "../scripts/tvs-up.sh" "$BUILD_DIR/"
  # Clean up the extra stuff in the folder.
  rm -rf "$TAR_DIR"
  rm -f "$BUILD_DIR/oak_containers_syslogd"
  rm "$BUILD_DIR/BUILD"
}
