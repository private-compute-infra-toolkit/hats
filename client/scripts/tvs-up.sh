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

echo "Running TVS server on port 7774"

./tvs-server_main \
        --primary_private_key="$(cat tvs_hold_noise_kk_private_key_hex)" \
        --user_key_id=64 \
        --user_public_key="$(cat public_hold_public_hpke_key_hex)" \
        --user_secret="$(cat tvs_hold_private_hpke_key_hex)" \
        --user_authentication_public_key="$(cat tvs_hold_user_authentication_public_key_hex)" \
        --port=7774 \
        --appraisal_policy_file='appraisal_policy.txtpb'
