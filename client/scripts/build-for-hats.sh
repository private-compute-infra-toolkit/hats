set -e

readonly SCRIPTS_DIR="$(dirname "$0")"
readonly PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"
cd "$SCRIPTS_DIR"
mkdir -p "$PREBUILT_DIR"

source ./build-lib.sh

TVS_PUBLIC_KEY=$1
build_kv_service
copy_vcek
pass_key_to_orchestrator $TVS_PUBLIC_KEY
build_oak_containers_kernel $PREBUILT_DIR
build_oak_containers_images $PREBUILT_DIR
build_oak_containers_launcher $PREBUILT_DIR
build_oak_containers_stage0 $PREBUILT_DIR
build_oak_containers_stage1 $PREBUILT_DIR
build_oak_hello_world_container_bundle_tar $PREBUILT_DIR
