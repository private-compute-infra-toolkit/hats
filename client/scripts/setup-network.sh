#!/bin/bash
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
