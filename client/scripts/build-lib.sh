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

function build_cloud_hypervisor() {
  local BUILD_DIR="$1"
  echo "BUILDING CLOUD HYPERVISOR..."
  pushd ../../submodules/oak/oak_on_prem_cloud_hypervisor
  rm -rf ./cloud-hypervisor-39.0 && \
    nix develop --command make && \
    sudo setcap cap_net_admin+ep target/cloud-hypervisor && \
    rsync target/cloud-hypervisor "$BUILD_DIR"
  popd
}

function build_kv_service() {
  printf "\nBUILDING KV SERVICE..."
  pushd ../../submodules/kv-server
  ./builders/tools/bazel-debian build //components/data_server/server:server \
    --//:platform=local \
    --//:instance=local
  rsync bazel-bin/components/data_server/server/server ../../client/prebuilt/kv-server
  popd
}

function build_oak_containers_kernel() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS KERNEL..."
  pushd ../../submodules/oak/oak_containers_kernel
  nix develop --command make clean && \
    nix develop --command make target/vanilla_bzImage && \
    rsync target/vanilla_bzImage "$BUILD_DIR"
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
    rsync ./stage0_bin/target/x86_64-unknown-none/release/stage0_bin "$BUILD_DIR"
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
  nix develop --command just oak_containers_hello_world_container_bundle_tar && \
    rsync ./oak_containers_hello_world_container/target/oak_container_example_oci_filesystem_bundle.tar "$BUILD_DIR"
  popd
}

function build_oak_kv_container_bundle_tar() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK KV CONTAINER BUNDLE TAR..."

  pushd ..
  readonly OCI_IMAGE_FILE="prebuilt/oak_container_kv_oci_image.tar"

  # Export the container as an OCI Image.
  # Ref: https://docs.docker.com/build/exporters/oci-docker/
  BUILDER="$(docker buildx create --driver docker-container)"
  readonly BUILDER
  docker buildx \
      --builder="${BUILDER}" \
      build \
      --file=kv.Dockerfile \
      --tag="latest" \
      --output="type=oci,dest=${OCI_IMAGE_FILE}" \
      .

  WORK_DIR="$(mktemp --directory)"
  readonly WORK_DIR
  readonly OUTPUT_OCI_BUNDLE_TAR="${BUILD_DIR}/oak_containers_kv_filesystem_bundle.tar"

  echo "[INFO] Exporting the container as an OCI image"
  readonly OCI_IMAGE_DIR="${WORK_DIR}/image"
  mkdir "${OCI_IMAGE_DIR}"
  tar --extract \
    --file="${OCI_IMAGE_FILE}" \
    --directory="${OCI_IMAGE_DIR}"

  echo "Unpacking with umoci..."
  readonly OCI_BUNDLE_DIR="${WORK_DIR}/bundle"
  # Deterministically extract the OCI image into an OCI bundle.
  # Note that in addition to this, umoci also creates an mtree spec in the same
  # dir. This mtree is not deterministic. Ref: https://github.com/opencontainers/umoci/blob/main/doc/man/umoci-unpack.1.md
  umoci unpack \
    --rootless \
    --image="${OCI_IMAGE_DIR}" \
    "${OCI_BUNDLE_DIR}"

  echo "[INFO] Creating runtime bundle"
  # Bundle just the files and directories that constitute the deterministically
  # generated OCI bundle.
  tar --create --file="${OUTPUT_OCI_BUNDLE_TAR}" --directory="${OCI_BUNDLE_DIR}" ./rootfs ./config.json

  popd
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
  echo "BUILDING LAUNCHER"
  bazel build -c opt //client/launcher:launcher
  cp -f ../../bazel-bin/client/launcher/launcher "$BUILD_DIR"
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
  nix develop --command just oak_containers_syslogd && \
    cp ./oak_containers_syslogd/target/oak_containers_syslogd_patched "$BUILD_DIR/oak_containers_syslogd"
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
