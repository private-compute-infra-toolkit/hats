#!/bin/bash
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

sudo ./launcher_main \
        --tvs_address=localhost:7774 \
        --use_tls=false \
        --launcher_config_path=launcher_config.prototext \
        --tvs_authentication_key="$(cat launcher_hold_user_authentication_private_key_hex)" \
        --minloglevel=0 \
        --stderrthreshold=0
