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

output "tvs_key_encryption_key_id" {
  value = module.tvs.tvs_key_encryption_key_id
}

output "tvs_db_instance_name" {
  value = module.tvs.tvs_db_instance_name
}

output "tvs_db_name" {
  value       = module.tvs.tvs_db_name
  description = "Name of the Spanner database"
}

output "tvs_cloudrun_url" {
  description = "The cloud run URL."
  value       = module.tvs.tvs_cloudrun_url
}

output "tvs_loadbalancer_ip" {
  value = module.tvs.tvs_loadbalancer_ip
}

output "tvs_base_url" {
  value = module.tvs.tvs_base_url
}
