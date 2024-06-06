#!/bin/bash

export TAP_DEV=tap0

sudo shortleash-upscript --cleanup
sudo ip link delete ${TAP_DEV}

unset TAP_DEV=tap0
