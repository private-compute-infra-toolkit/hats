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

output "tvs_db_instance_name" {
  value       = module.tvs_db.tvs_db_instance_name
  description = "Name of the Spanner database instance"
}

output "tvs_db_name" {
  value       = module.tvs_db.tvs_db_name
  description = "Name of the Spanner database"
}

output "tvs_key_encryption_key_id" {
  value = module.tvs_db.tvs_key_encryption_key_id
  description = "Name of the KEK used for database"
}

output "tvs_key_encryption_ring_id" {
  value =  module.tvs_db.tvs_key_encryption_ring_id
  description = "Name of the key encryption ring containing KEK used for database"
}
