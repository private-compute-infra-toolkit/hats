#!/bin/bash

set -e

readonly SCRIPTS_DIR="$(dirname "$0")"
readonly PREBUILT_DIR="$(readlink -f "$SCRIPTS_DIR/../prebuilt")"

sudo ${PREBUILT_DIR}/cloud-hypervisor \
  --seccomp false \
  --kernel ${PREBUILT_DIR}/bzImage \
  --disk path=${PREBUILT_DIR}/output.img \
  --cmdline "console=hvc0 root=/dev/vda rw" \
  --cpus boot=4 \
  --memory size=2048M \
  --net "tap=tap0" \
  -v
