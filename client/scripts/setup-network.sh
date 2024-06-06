#!/bin/bash

# Prerequisite: shortleash
# sudo glinux-add-repo shortleash
# sudo apt update
# sudo apt install shortleash
# ls -l /usr/bin/shortleash-upscript

export TAP_DEV=tap0

sudo shortleash-upscript --cleanup
sudo ip link delete ${TAP_DEV}

sudo ip tuntap add dev ${TAP_DEV} mode tap user $USER && sudo ip link set ${TAP_DEV} up || exit 1
sudo shortleash-upscript ${TAP_DEV} || exit 1

unset TAP_DEV
