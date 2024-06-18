set -e

readonly SCRIPTS_DIR="$(dirname "$0")"
readonly PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"

# The oak_containers_launcher has hardcoded AMD SEV-SNP parameters
sudo ${PREBUILT_DIR}/oak_containers_launcher \
  --system-image ${PREBUILT_DIR}/image-old.tar.xz \
  --container-bundle ${PREBUILT_DIR}/oak_container_example_oci_filesystem_bundle.tar \
  --vmm-binary ${PREBUILT_DIR}/qemu-system-x86_64 \
  --stage0-binary ${PREBUILT_DIR}/stage0_bin \
  --kernel ${PREBUILT_DIR}/bzImage \
  --initrd ${PREBUILT_DIR}/stage1.cpio \
  --memory-size="8G" \
  --ramdrive-size="10000000" \
  --vm-type sev-snp \
  --tvs-address $1
