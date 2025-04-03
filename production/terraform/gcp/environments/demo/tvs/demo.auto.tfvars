# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

environment    = "<environment name>"
project_id     = "<project id>"
primary_region = "us-central1"

# Output from tvs_db
tvs_spanner_database_name  = "<tvs_spanner_database_name>"
tvs_spanner_instance_name  = "<tvs_spanner_instance_name>"
tvs_key_encryption_ring_id = "<tvs_key_encryption_ring_id>"

coordinator_project_id = "<coordinator_project_id>"
coordinator_spanner_database_name  = "<coordinator_spanner_database_name>"
coordinator_spanner_instance_name  = "<coordinator_spanner_instance_name>"

# The container image of Cloud Run service deployment for TVS.
tvs_image = "<url_to_tvs_image>"
