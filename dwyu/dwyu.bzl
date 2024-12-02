# Copyright 2024 Google LLC
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

load("@depend_on_what_you_use//:defs.bzl", "dwyu_aspect_factory")

### dwyu_ignore_includes.json
#   Includes that are come transitively (linux/types.h)
#   Includes that are hard to have deps (cpuid.h)
#   Includes it incorrectly says unused (grpcpp)
### Additional things w/o manual skip, that must be manually ignored
# "@com_github_grpc_grpc//:grpc++", may incorrectly be said unused
#   (or the reflect version)
# rust_cxx_bridge rules, doesn't accept tags that let it be skipped
#   any .rs.h, as missing dep, or deps within

# Recursive .rs.h oddly are fixed by pragma once but not include guards

hats_dwyu_aspect = dwyu_aspect_factory(
    skipped_tags = ["rust-bridge", "grpc"],
    skip_external_targets = True,
    ignored_includes = Label("@//dwyu:dwyu_ignore_includes"),
)
