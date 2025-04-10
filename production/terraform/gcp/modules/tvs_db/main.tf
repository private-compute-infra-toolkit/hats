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

# Cloud KMS encryption ring and key encryption key (KEK)
resource "google_kms_key_ring" "key_encryption_ring" {
  project  = var.project_id
  name     = "${var.environment}_key_encryption_ring"
  location = "us"
}

resource "google_kms_crypto_key" "key_encryption_key" {
  name     = "${var.environment}_key_encryption_key"
  key_ring = google_kms_key_ring.key_encryption_ring.id

  # Setting KMS key rotation to yearly
  rotation_period = "31536000s"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_spanner_instance" "tvs_db_instance" {
  project          = var.project_id
  name             = "${var.environment}-tvs-dbinstance"
  display_name     = "${var.environment}-tvs-dbinstance"
  config           = var.spanner_instance_config
  processing_units = var.spanner_processing_units
}

resource "google_spanner_database" "tvs_db" {
  project                  = var.project_id
  instance                 = google_spanner_instance.tvs_db_instance.name
  name                     = "${var.environment}-tvsdb"
  version_retention_period = var.tvs_db_retention_period

  deletion_protection = true
}

resource "google_service_account" "tvs_service_account" {
  project = var.project_id
  # Service account id has a 30 character limit
  account_id   = "${var.environment}-tvsuser"
  display_name = "TVS Service Account"
}

# IAM entry for service account to read/write the database
resource "google_spanner_database_iam_member" "tvs_spannerdb_iam_policy" {
  project  = var.project_id
  instance = google_spanner_instance.tvs_db_instance.name
  database = google_spanner_database.tvs_db.name
  role     = "roles/spanner.databaseReader"
  member   = "serviceAccount:${google_service_account.tvs_service_account.email}"
}

# Allow TVS service account to encrypt/decrypt
resource "google_kms_key_ring_iam_member" "tvs_key_encryption_ring_iam" {
  key_ring_id = google_kms_key_ring.key_encryption_ring.id
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member      = "serviceAccount:${google_service_account.tvs_service_account.email}"
}

# Allow TVS service account to encrypt/decrypt
resource "google_project_iam_member" "tvs_metrics_writer_iam" {
  project     = var.project_id
  role        = "roles/monitoring.metricWriter"
  member      = "serviceAccount:${google_service_account.tvs_service_account.email}"
}
