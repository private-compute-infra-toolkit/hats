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

################################################################################
# Global Variables.
################################################################################

variable "project_id" {
  description = "GCP Project ID in which this module will be created."
  type        = string
}

variable "environment" {
  description = "Description for the environment, e.g. dev, staging, production."
  type        = string
}

variable "primary_region" {
  description = "Region where all services will be created."
  type        = string
}

################################################################################
# Cloud Run Variables.
################################################################################

variable "tvs_cloudrun_memory_mb" {
  description = "Memory size in MB for cloudrun."
  type        = number
}

variable "tvs_cloudrun_min_instances" {
  description = "The minimum number of container instances that may coexist at a given time."
  type        = number
}

variable "tvs_cloudrun_max_instances" {
  description = "The maximum number of container instances that may coexist at a given time."
  type        = number
}

variable "tvs_request_concurrency" {
  description = "The maximum number of requests to allow to be concurrently processed by a container instance."
  type        = number
}

variable "tvs_cpus" {
  description = "The number of CPUs used in a single container instance."
  type        = number
}

variable "cloudrun_timeout_seconds" {
  description = "Number of seconds after which a container instance times out."
  type        = number
}

variable "cloud_run_revision_force_replace" {
  description = "Whether to create a new Cloud Run revision for every deployment."
  type        = bool
}

variable "tvs_image" {
  description = "The container image of Cloud Run service deployment for TVS."
  type        = string
}

variable "tvs_custom_audiences" {
  description = "List of custom audiences for TVS on Cloud Run."
  type        = list(string)
}

variable "allow_unauthenticated" {
  description = "Whether to allow unauthenticated requests."
  type        = bool
}

variable "allowed_operator_user_group" {
  description = "Google group of allowed operators to which to give API access. Required when allow_unauthenticated is false."
  type        = string
}

variable "enable_dynamic_policy_fetching" {
  description = "Enable dynamic policy fetching for TVS."
  type        = bool
}

variable "tvs_spanner_database_name" {
  description = "Name of the TvsDb Spanner database."
  type        = string
}

variable "tvs_spanner_instance_name" {
  description = "Name of the TvsDb Spanner instance."
  type        = string
}

variable "tvs_service_account" {
  type = string
  description = "Name of the TVS service account email"
}

variable "coordinator_spanner_database_name" {
  description = "Name of the Coordinator Spanner database."
  type        = string
}

variable "coordinator_spanner_instance_name" {
  description = "Name of the Coordinator Spanner instance."
  type        = string
}

variable "coordinator_project_id" {
  type        = string
  description = "The GCP project ID of the coordinator Spanner instance."
}

################################################################################
# Routing Variables.
################################################################################

variable "enable_domain_management" {
  description = "Manage domain SSL cert creation and routing for this service."
  type        = bool
}

variable "parent_domain_name" {
  description = <<-EOT
    Custom domain name to register and use with key hosting APIs.
    Default to null so it does not have to be populated when enable_domain_management = false".
  EOT
  type        = string
  default     = null
}

variable "parent_domain_name_project" {
  description = <<-EOT
    Project ID where custom domain name hosted zone is located.
    Default to null so it does not have to be populated when enable_domain_management = false".
  EOT
  type        = string
  default     = null
}

variable "service_subdomain_suffix" {
  description = "When set, the value replaces `-$${var.environment}` as the service subdomain suffix."
  type        = string
  default     = null
}

variable "tvs_subdomain" {
  description = "Subdomain to use to create a managed SSL cert for this service."
  type        = string
}
