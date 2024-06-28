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
  cp -f certificates/vcek_genoa.crt ../submodules/oak/oak_containers_system_image/target/vcek_genoa.crt
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
