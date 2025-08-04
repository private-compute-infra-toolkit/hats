#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


##### Launch Docker to build the test binaries.
docker_run_flags=(
  '--rm'
  '--workdir=/workspace'
  '--network=host'
  '--security-opt=seccomp=unconfined'
  # BIND MOUNTS - Make host directories available in container.
  "--mount=type=bind,source=./,target=/workspace"
  # This prevent bazel from having to re-populate the cache every time you start
  # your local docker container.
  '--mount=type=volume,src=bazel-cache,target=/root/.cache/bazel'
)

DOCKER_IMAGE_ID="us-central1-docker.pkg.dev/ps-hats-playground/presubmit/presubmit@sha256:2249f8185aa452c63ad76f0721c10f7ddff8bc26b4e0a36f8e682f264b3f1057"

docker run "${docker_run_flags[@]}" $DOCKER_IMAGE_ID "$@"
