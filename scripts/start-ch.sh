#!/bin/bash

sudo ./cloud-hypervisor \
  --seccomp false \
  --kernel ./bzImage \
  --disk path=output.img \
  --cmdline "console=hvc0 root=/dev/vda rw" \
  --cpus boot=4 \
  --memory size=2048M \
  --net "tap=tap0" \
  -v
