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
    cp -f target/cloud-hypervisor "$BUILD_DIR"
  popd
}

function build_kv_service() {
  printf "\nBUILDING KV SERVICE..."
  pushd ../../submodules/kv-server
  ./builders/tools/bazel-debian build //components/data_server/server:server \
    --//:platform=local \
    --//:instance=local
  mkdir -p ../../submodules/oak/oak_containers_system_image/target/
  cp -f bazel-bin/components/data_server/server/server ../../submodules/oak/oak_containers_system_image/target/kv-server
  popd
}

function copy_vcek() {
  printf "\nCOPY VCEK ..."
  pushd ../
  mkdir -p ../submodules/oak/oak_containers_system_image/target
  cp -f certificates/vcek_genoa.crt ../submodules/oak/oak_containers_system_image/target/vcek_genoa.crt
  echo "COPY ./target/vcek_genoa.crt /usr/vcek_genoa.crt" >> ../submodules/oak/oak_containers_system_image/Dockerfile
  popd
}

function build_oak_containers_kernel() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS KERNEL..."
  pushd ../../submodules/oak/oak_containers_kernel
    nix develop --command make clean && \
    nix develop --command make target/vanilla_bzImage && \
    cp -f target/vanilla_bzImage "$BUILD_DIR"
  popd
}

function build_oak_containers_images() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS IMAGES..."
  pushd ../../submodules/oak/oak_containers_system_image
  nix develop --command ./build-old.sh && \
    mv target/output.img "$BUILD_DIR" && \
    mv target/image-old.tar "$BUILD_DIR" && \
    xz --force "$BUILD_DIR/image-old.tar"
  popd
}

function build_oak_containers_launcher() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS LAUNCHER..."
  pushd ../../submodules/oak
  nix develop --command just oak_containers_launcher && \
    mv ./target/x86_64-unknown-linux-gnu/release/oak_containers_launcher "$BUILD_DIR"
  popd
}

function build_oak_containers_stage0() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS STAGE0..."
  pushd ../../submodules/oak
  nix develop --command just stage0_bin && \
    mv ./stage0_bin/target/x86_64-unknown-none/release/stage0_bin "$BUILD_DIR"
  popd
}

function build_oak_containers_stage1() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK CONTAINERS STAGE1..."
  pushd ../../submodules/oak
    nix develop --command just stage1_cpio && \
    mv ./target/stage1.cpio "$BUILD_DIR"
  popd
}

function build_oak_hello_world_container_bundle_tar() {
  local BUILD_DIR="$1"
  printf "\nBUILDING OAK HELLO WORLD CONTAINER BUNDLE TAR..."
  pushd ../../submodules/oak
  nix develop --command just oak_containers_hello_world_container_bundle_tar && \
    mv ./oak_containers_hello_world_container/target/oak_container_example_oci_filesystem_bundle.tar "$BUILD_DIR"
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


pass_key_to_orchestrator() {
  local TVS_PUBLIC_KEY=$1
  echo "PASS KEY TO ORCHESTRATOR"
  pushd ../../submodules/oak
cat << EOF > ./oak_containers_system_image/files/etc/systemd/system/oak-orchestrator.service
[Unit]
Description=Oak Containers Orchestrator
After=network-online.target
Wants=network-online.target
#FailureAction=poweroff-force
#SuccessAction=poweroff-force
FailureAction=none
SuccessAction=none

[Service]
Type=simple
ExecStart=/bin/oak_containers_orchestrator --container-dir \${RUNTIME_DIRECTORY}/oak_container --ipc-socket-path \${RUNTIME_DIRECTORY}/oak_utils/orchestrator_ipc --tvs-public-key=$TVS_PUBLIC_KEY
ExecStopPost=/usr/bin/journalctl --sync --flush
ProtectSystem=strict
RuntimeDirectory=oak_containers_orchestrator
ReadWritePaths=/oak

[Install]
WantedBy=multi-user.target
EOF
  popd
}

function build_hats_launcher() {
  local BUILD_DIR="$1"
  echo "BUILDING LAUNCHER"
  bazel build -c opt //client/launcher:launcher
  cp -f ../../bazel-bin/client/launcher/launcher $BUILD_DIR
  cp -r ../test_data/parc_data $BUILD_DIR
}

function build_parc_containers_images() {
  local BUILD_DIR="$1"
  echo "BUILDING ORCHESTRATOR"
  bazel build -c opt //client/orchestrator:orchestrator_main
  cp -f ../../bazel-bin/client/orchestrator/orchestrator_main ../../submodules/oak/oak_containers_system_image/target/oak_containers_orchestrator
  echo "COPY APPLICATION BINARIES"
  mkdir -p ../../submodules/oak/oak_containers_system_image/target
  cp -f $BUILD_DIR/../scripts/launch-trusted-app.sh ../../submodules/oak/oak_containers_system_image/target/
  cp -f $BUILD_DIR/trusted-app ../../submodules/oak/oak_containers_system_image/target/
  printf "\nBUILDING PARC CONTAINERS IMAGES..."
  pushd ../../submodules/oak/oak_containers_system_image
cat << EOF > Dockerfile
ARG debian_snapshot=sha256:f0b8edb2e4436c556493dce86b941231eead97baebb484d0d5f6ecfe4f7ed193
FROM debian@\${debian_snapshot}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get --yes update \
  && apt-get install --yes --no-install-recommends \
  systemd systemd-sysv dbus udev runc net-tools isc-dhcp-client iproute2 \
  && apt-get clean && rm --recursive --force /var/lib/apt/lists/*

# Clean up some stuff we don't need
RUN rm -rf /usr/share/doc /usr/share/info /usr/share/man

# Copy config files
COPY files /

# Prepare network
RUN systemctl enable systemd-networkd

# Copy the orchestartor binary & service
COPY ./target/oak_containers_orchestrator /usr/bin/oak_containers_orchestrator
RUN systemctl enable oak-orchestrator

# Log relay
COPY ./target/oak_containers_syslogd_patched /usr/bin/oak_containers_syslogd
RUN systemctl enable oak-syslogd

COPY ./target/trusted-app /usr/bin/trusted-app

COPY ./target/launch-trusted-app.sh /usr/bin

# Metrics agent
COPY ./target/oak_containers_agent_patched /usr/bin/oak_containers_agent
RUN systemctl enable oak-agent

# Only enable interactive logins if the kernel was booted with "debug" flag.
RUN systemctl disable getty@
RUN systemctl enable root-passwd

# Don't bother starting the graphical interface, let's stick with the basic multi-user target.
RUN systemctl set-default multi-user

RUN echo kvserver.local > /etc/hostname

RUN mkdir /deltas
RUN mkdir /realtime
COPY ./target/vcek_genoa.crt /usr/vcek_genoa.crt
EOF

cat << EOF > ./build-for-parc.sh
#!/bin/bash

set -o xtrace
set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPTS_DIR="\$(dirname "\$0")"

cd "\$SCRIPTS_DIR"
mkdir --parent target

cargo build --package=oak_containers_syslogd --release -Z unstable-options --out-dir=./target
cargo build --package=oak_containers_agent --release -Z unstable-options --out-dir=./target

cp ./target/oak_containers_syslogd ./target/oak_containers_syslogd_patched
cp ./target/oak_containers_agent ./target/oak_containers_agent_patched

patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 ./target/oak_containers_syslogd_patched
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 ./target/oak_containers_agent_patched

chmod --recursive a+rX files/

docker build . --tag=oak-containers-system-image:latest
readonly NEW_DOCKER_CONTAINER_ID="\$(docker create oak-containers-system-image:latest)"

docker export "\$NEW_DOCKER_CONTAINER_ID" > target/image-old.tar
ls -lah target/image-old.tar
tar --append --file=target/image-old.tar --directory=files etc/hosts

virt-make-fs --format=qcow2 --type=ext4 --size=512M target/image-old.tar target/output.img

docker rm "\$NEW_DOCKER_CONTAINER_ID"

EOF
  chmod +x ./build-for-parc.sh
  nix develop --command ./build-for-parc.sh && \
    mv target/output.img "$BUILD_DIR" && \
    mv target/image-old.tar "$BUILD_DIR" && \
    xz --force "$BUILD_DIR/image-old.tar"
  popd
}
