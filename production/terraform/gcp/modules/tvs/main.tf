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

resource "google_service_account" "tvs_service_account" {
  project = var.project_id
  # Service account id has a 30 character limit
  account_id   = "${var.environment}-tvsuser"
  display_name = "TVS Service Account"
}

# IAM entry for service account to read/write the database
resource "google_spanner_database_iam_member" "tvs_spannerdb_iam_policy" {
  project  = var.project_id
  instance = var.spanner_instance_name
  database = var.spanner_database_name
  role     = "roles/spanner.databaseUser"
  member   = "serviceAccount:${google_service_account.tvs_service_account.email}"
}

# Allow TVS service account to encrypt/decrypt
resource "google_kms_key_ring_iam_member" "key_encryption_ring_iam" {
  key_ring_id = google_kms_key_ring.key_encryption_ring.id
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member      = "serviceAccount:${google_service_account.tvs_service_account.email}"
}

# IAM entry to invoke allow unauthenticated
resource "google_cloud_run_service_iam_binding" "allow_unauthenticated_iam_policy" {
  count = var.allow_unauthenticated ? 1 : 0

  project  = var.project_id
  location = google_cloud_run_v2_service.tvs.location
  service  = google_cloud_run_v2_service.tvs.name
  role     = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

# IAM entry to invoke the cloud run service.
resource "google_cloud_run_service_iam_member" "private_key_service" {
  count = !var.allow_unauthenticated ? 1 : 0

  project  = var.project_id
  location = google_cloud_run_v2_service.tvs.location
  service  = google_cloud_run_v2_service.tvs.name

  role   = "roles/run.invoker"
  member = "group:${var.allowed_operator_user_group}"
}

# Cloud Run Service
resource "google_cloud_run_v2_service" "tvs" {
  project  = var.project_id
  name     = "${var.environment}-${var.region}-tvs"
  location = var.region
  # Terraform google_compute_backend_service does not currently support H2C which is needed for unauthenticated GRPC.
  # A load balancer will not be created if enable_domain_management is not enabled.
  ingress = var.enable_domain_management ? "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER" : "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = var.tvs_image
      args = ["--project_id=${var.project_id}",
        "--instance_id=${var.spanner_instance_name}",
        "--database_id=${var.spanner_database_name}",
        "--enable_dynamic_policy_fetching=${var.enable_dynamic_policy_fetching}",
      "--stderrthreshold=0"]

      resources {
        limits = {
          cpu    = var.tvs_cpus
          memory = "${var.tvs_cloudrun_memory_mb}M"
        }
      }

      ports {
        name           = "h2c"
        container_port = 8080
      }
    }

    scaling {
      min_instance_count = var.tvs_cloudrun_min_instances
      max_instance_count = var.tvs_cloudrun_max_instances
    }

    max_instance_request_concurrency = var.tvs_request_concurrency
    timeout                          = "${var.cloudrun_timeout_seconds}s"

    labels = {
      # Create a new revision if cloud_run_revision_force_replace is true. This
      # is done by applying a unique timestamp label on each deployment.
      force_new_revision_timestamp = var.cloud_run_revision_force_replace ? formatdate("YYYY-MM-DD_hh_mm_ss", timestamp()) : null,
    }

    service_account = google_service_account.tvs_service_account.email
  }

  custom_audiences = var.tvs_custom_audiences
}
