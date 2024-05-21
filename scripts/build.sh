set -e

readonly SCRIPTS_DIR="$(dirname "$0")"
cd "$SCRIPTS_DIR"

echo "BUILDING CLOUD HYPERVISOR..."
pushd ../submodules/oak/oak_on_prem_cloud_hypervisor
rm -rf ./cloud-hypervisor-38.0 && \
  make && \
  sudo setcap cap_net_admin+ep target/cloud-hypervisor && \
  cp target/cloud-hypervisor ../../../cloud-hypervisor
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
make clean && make && \
  cp -f target/bzImage ../../../
popd

printf "\nBUILDING OAK CONTAINERS IMAGES..."
pushd ../submodules/oak/oak_containers_system_image
nix develop --command ./build-old.sh && \
  mv target/output.img ../../../
popd
