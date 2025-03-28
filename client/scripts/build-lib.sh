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

# Use oak scripts/docker_run if env var USE_OAK_DOCKER set
# Needs oak scripts/docker_pull first to get the image
# Similar to standard nix develop, only call from within oak (e.g. submodule)
function nix_develop() {
  if [[ "$USE_OAK_DOCKER" == 1 ]]; then
    ./scripts/docker_run nix develop "$@"
  else
    nix develop "$@"
  fi
}

function build_oak_containers_kernel() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS KERNEL..."
  pushd ../../submodules/oak/
  nix_develop --extra-experimental-features 'nix-command flakes' --command just oak_containers_kernel && \
    rsync artifacts/oak_containers_kernel "$BUILD_DIR//bzImage"
  popd
}

function build_oak_containers_images() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS IMAGES..."
  pushd ../../submodules/oak/oak_containers_system_image
  nix_develop --extra-experimental-features 'nix-command flakes' --command ./build-old.sh && \
    rsync target/output.img "$BUILD_DIR" && \
    rsync target/image-old.tar "$BUILD_DIR" && \
    xz --force "$BUILD_DIR/image-old.tar"
  popd
}

function build_oak_containers_launcher() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS LAUNCHER..."
  pushd ../../submodules/oak
  nix_develop --extra-experimental-features 'nix-command flakes' --command just oak_containers_launcher && \
    rsync ./target/x86_64-unknown-linux-gnu/release/oak_containers_launcher "$BUILD_DIR"
  popd
}

function build_oak_containers_stage0() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS STAGE0..."
  pushd ../../submodules/oak
  nix_develop --extra-experimental-features 'nix-command flakes' --command just stage0_bin && \
    rsync ./artifacts/stage0_bin "$BUILD_DIR"
  popd
}

function build_oak_containers_stage1() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS STAGE1..."
  pushd ../../submodules/oak
  nix_develop --extra-experimental-features 'nix-command flakes' --command just stage1_cpio && \
    rsync ./artifacts/stage1.cpio "$BUILD_DIR"
  popd
}

function build_oak_hello_world_container_bundle_tar() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK HELLO WORLD CONTAINER BUNDLE TAR..."
  pushd ../../submodules/oak
  # just command to build the container tries to copy a file to
  # a folder it doesn't have permission to do so and it fails at that
  # step; so here we copy after we call `just`.
  nix_develop --extra-experimental-features 'nix-command flakes' --command  bazel build --compilation_mode opt //oak_containers/examples/hello_world/trusted_app:bundle.tar && \
    rsync ./bazel-bin/oak_containers/examples/hello_world/trusted_app/bundle.tar "$BUILD_DIR/oak_container_example_oci_filesystem_bundle.tar"

  popd
}

function build_test_application_container_bundle_tar() {
  local BUILD_DIR="$1"
  printf "\nBUILDING TEST APPLICATION CONTAINER BUNDLE TAR..."
  bazel build -c opt //client/trusted_application:bundle
  cp -f ../../bazel-bin/client/trusted_application/bundle.tar "$BUILD_DIR"
}

function build_trusted_application_client() {
  local BUILD_DIR="$1"
  printf "\nBUILDING TRUSTED APPLICATION CLIENT..."
  bazel build -c opt //client/trusted_application:trusted_application_client_main
  cp -f ../../bazel-bin/client/trusted_application/trusted_application_client_main "$BUILD_DIR"
}

function build_snphost() {
  local BUILD_DIR="$1"
  pushd ../../submodules/oak
  nix_develop --extra-experimental-features 'nix-command flakes' --command cargo install --root "$BUILD_DIR" snphost && \
    mv "$BUILD_DIR"/bin/snphost "$BUILD_DIR" && \
    rmdir "$BUILD_DIR/bin"
  popd
}

function build_hats_launcher() {
  local BUILD_DIR="$1"
  echo "BUILDING LAUNCHER CC"
  bazel build -c opt //client/launcher:launcher_main
  cp -f ../../bazel-bin/client/launcher/launcher_main "$BUILD_DIR"
}

function build_oak_containers_syslogd() {
  local BUILD_DIR="$1"
  cat << EOF > "$BUILD_DIR/BUILD"
exports_files([
  "oak_containers_syslogd",
])
EOF
  printf "\nBUILDING OAK CONTAINERS SYSLOGD"
  . /etc/os-release
  if [[ "$ID" == "centos" ]]
  then
    printf "\nCentOS requires building inside a docker container to prevent linking issue"
    pushd ../../submodules/oak
    docker build . --tag local_oak_builder:latest
    popd
    pushd ../..
    docker run -v "$(readlink -f .)":/workspace -v "$(readlink -f "$BUILD_DIR")":/hats_build -w /workspace local_oak_builder:latest /bin/bash -c "
    cd /workspace/submodules/oak && git config --global --add safe.directory /workspace/submodules/oak && git status && \
    nix develop --extra-experimental-features 'nix-command flakes' \
      --command bazel build -c opt //oak_containers/syslogd:oak_containers_syslogd && \
    cp -f bazel-bin/oak_containers/syslogd/oak_containers_syslogd /hats_build/oak_containers_syslogd"
    popd
  else
    pushd ../../submodules/oak
    if [[ "$USE_OAK_DOCKER" == 1 ]]; then
      # bazel-bin in docker_run is local, so copy in same run
      # Also oak docker script doesn't see hats, so artifact as middle
      ./scripts/docker_run /bin/bash -c "nix develop --command bazel build -c opt //oak_containers/syslogd:oak_containers_syslogd && \
        cp -f bazel-bin/oak_containers/syslogd/oak_containers_syslogd artifacts/oak_containers_syslogd"
      rsync artifacts/oak_containers_syslogd "$BUILD_DIR/oak_containers_syslogd"
    else
      nix develop --command bazel build -c opt //oak_containers/syslogd:oak_containers_syslogd && \
        cp -f bazel-bin/oak_containers/syslogd/oak_containers_syslogd "$BUILD_DIR/oak_containers_syslogd"
    fi

    popd
  fi
}

function build_hats_containers_images() {
  local BUILD_DIR="$1"
  bazel build -c opt //client/system_image:hats_system_image --//:syslogd_source=binary
  cp -f ../../bazel-bin/client/system_image/hats_system_image.tar "$BUILD_DIR"
  xz --force "$BUILD_DIR/hats_system_image.tar"
}

function build_tvs() {
  local BUILD_DIR="$1"
  bazel build -c opt //tvs/standalone_server:tvs-server_main
  cp -f ../../bazel-bin/tvs/standalone_server/tvs-server_main "$BUILD_DIR"
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
  # We force the reproducibility of the system bundle to prevent confusion that
  # the underlying binaries are of a different version.
  tar --mode a=rx,u+w --mtime='@0' --sort=name --owner=root:0 --group=root:0 -C "$TAR_DIR" -cf "$BUILD_DIR/system_bundle.tar" .
  mv -f "$RUNTIME" "$BUILD_DIR/runtime_bundle.tar"
  cp "$LAUNCHER_CONFIG" "$BUILD_DIR/launcher_config.txtpb"
  cp "$APPRISAL_POLICY" "$BUILD_DIR/appraisal_policy.txtpb"
  # Init script to generate fake test keys.
  cp "../scripts/keygen-local-init.sh" "$BUILD_DIR/"
  cp "../scripts/launcher-up.sh" "$BUILD_DIR/"
  cp "../scripts/tvs-up.sh" "$BUILD_DIR/"
  # Clean up the extra stuff in the folder.
  rm -rf "$TAR_DIR"
  rm -f "$BUILD_DIR/oak_containers_syslogd"
  rm "$BUILD_DIR/BUILD"
}

# A tar file contains all launch required data.
# A textproto file contains all launch parameters.
# Secrets are in parameters only.
function build_test_bundles() {
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
  # We force the reproducibility of the system bundle to prevent confusion that
  # the underlying binaries are of a different version.
  tar --mode a=r,u+w,a+X --mtime='@0' --sort=name --owner=root:0 --group=root:0 -C "$TAR_DIR" -cf "$BUILD_DIR/system_bundle.tar" .
  mv -f "$RUNTIME" "$BUILD_DIR/runtime_bundle.tar"
  # Clean up the extra stuff in the folder.
  rm -rf ../prebuilt
  rm -rf "$TAR_DIR"
  rm -f "$BUILD_DIR/oak_containers_syslogd"
}
