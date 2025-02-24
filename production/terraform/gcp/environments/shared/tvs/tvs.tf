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

########################
# DO NOT EDIT MANUALLY #
########################

# This file is meant to be shared across all environments (either copied or
# symlinked). In order to make the upgrade process easier, this file should not
# be modified for environment-specific customization.

module "tvs" {
  source = "../../../applications/tvs"

  project_id     = var.project_id
  environment    = var.environment
  primary_region = var.primary_region

  spanner_instance_config  = var.spanner_instance_config
  spanner_processing_units = var.spanner_processing_units

  # Cloud Run vars
  cloudrun_timeout_seconds         = var.cloudrun_timeout_seconds
  tvs_cloudrun_memory_mb           = var.tvs_cloudrun_memory_mb
  tvs_cloudrun_min_instances       = var.tvs_cloudrun_min_instances
  tvs_cloudrun_max_instances       = var.tvs_cloudrun_max_instances
  tvs_request_concurrency          = var.tvs_request_concurrency
  tvs_cpus                         = var.tvs_cpus
  cloud_run_revision_force_replace = var.cloud_run_revision_force_replace
  tvs_image                        = var.tvs_image
  tvs_custom_audiences             = var.tvs_custom_audiences
  allow_unauthenticated            = var.allow_unauthenticated
  allowed_operator_user_group      = var.allowed_operator_user_group
}
