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

# Note: Multi region can be used but is roughly 4x the cost.
# nam10 is North America - uscentral1 and uswest3:
# https://cloud.google.com/spanner/docs/instance-configurations#configs-multi-region
spanner_instance_config = "nam10"

# Spanner's compute capacity. 1000 processing units = 1 node and must be set as a multiple of 100.
spanner_processing_units = 100
