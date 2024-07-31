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

# Remove files we don't want to publish before pushing to github.  We'll
# eventually move to CopyBara, but the overhead for CopyBara to update github,
# rather than the other way around, is fairly high.

rm "$(find . -name METADATA)"
rm "$(find . -name GOOGLE.md)"
rm -r google_internal releasing
