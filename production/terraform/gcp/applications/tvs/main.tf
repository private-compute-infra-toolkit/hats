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

locals {
  service_subdomain_suffix = var.service_subdomain_suffix != null ? var.service_subdomain_suffix : "-${var.environment}"
  parent_domain_name       = var.parent_domain_name != null ? var.parent_domain_name : ""
  tvs_domain               = var.environment != "prod" ? "${var.tvs_subdomain}${local.service_subdomain_suffix}.${local.parent_domain_name}" : "${var.tvs_subdomain}.${local.parent_domain_name}"
}

module "tvs" {
  source = "../../modules/tvs"

  environment = var.environment
  project_id  = var.project_id
  region      = var.primary_region

  # Cloud Run vars
  spanner_database_name            = module.tvs_db.tvs_db_name
  spanner_instance_name            = module.tvs_db.tvs_db_instance_name
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
  enable_dynamic_policy_fetching   = var.enable_domain_management

  # Domain Management
  enable_domain_management = var.enable_domain_management
  tvs_domain               = local.tvs_domain
  # domain_a_records
  parent_domain_name         = var.parent_domain_name
  parent_domain_name_project = var.parent_domain_name_project

  service_domain_to_address_map = var.enable_domain_management ? {
    (local.tvs_domain) : module.tvs.tvs_loadbalancer_ip
  } : {}
}

module "tvs_db" {
  source = "../../modules/tvs_db"

  project_id               = var.project_id
  environment              = var.environment
  spanner_instance_config  = var.spanner_instance_config
  spanner_processing_units = var.spanner_processing_units
  tvs_db_retention_period  = var.tvs_db_retention_period
}
