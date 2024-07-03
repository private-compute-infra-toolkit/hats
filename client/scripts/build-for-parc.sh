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

readonly SCRIPTS_DIR="$(dirname "$0")"
readonly PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"
cd "$SCRIPTS_DIR"
mkdir -p "$PREBUILT_DIR"

source ./build-lib.sh

TVS_PUBLIC_KEY=$1
copy_vcek
pass_key_to_orchestrator $TVS_PUBLIC_KEY
build_oak_containers_stage0 $PREBUILT_DIR
build_oak_containers_stage1 $PREBUILT_DIR
build_oak_containers_kernel $PREBUILT_DIR
build_hats_launcher $PREBUILT_DIR
build_parc_containers_images $PREBUILT_DIR
build_oak_hello_world_container_bundle_tar $PREBUILT_DIR
