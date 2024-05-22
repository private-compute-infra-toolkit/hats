set -e

readonly SCRIPTS_DIR="$(dirname "$0")"
readonly PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"
cd "$SCRIPTS_DIR"
mkdir -p "$PREBUILT_DIR"

echo "BUILDING CLOUD HYPERVISOR..."
pushd ../submodules/oak/oak_on_prem_cloud_hypervisor
rm -rf ./cloud-hypervisor-39.0 && \
  nix develop --command make && \
  sudo setcap cap_net_admin+ep target/cloud-hypervisor && \
  cp target/cloud-hypervisor "$PREBUILT_DIR"
popd

printf "\nBUILDING KV SERVICE..."
pushd ../submodules/kv-server
./builders/tools/bazel-debian build //components/data_server/server:server \
  --//:platform=local \
  --//:instance=local
mkdir -p ../../submodules/oak/oak_containers_system_image/target/
cp -f bazel-bin/components/data_server/server/server ../../submodules/oak/oak_containers_system_image/target/kv-server
popd

printf "\nBUILDING OAK CONTAINERS KERNEL..."
pushd ../submodules/oak/oak_containers_kernel
nix develop --command make clean && \
  nix develop --command make && \
  cp -f target/bzImage "$PREBUILT_DIR"
popd

printf "\nBUILDING OAK CONTAINERS IMAGES..."
pushd ../submodules/oak/oak_containers_system_image
nix develop --command ./build-old.sh && \
  mv target/output.img "$PREBUILT_DIR"
  mv target/image-old.tar "$PREBUILT_DIR"
popd

printf "\nBUILDING OAK CONTAINERS LAUNCHER..."
pushd ../submodules/oak
nix develop --command just oak_containers_launcher && \
  mv ./target/x86_64-unknown-linux-gnu/release/oak_containers_launcher "$PREBUILT_DIR"
popd
