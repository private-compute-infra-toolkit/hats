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

resource "google_secret_manager_secret" "otel_parameter" {
  project     = var.project_id
  secret_id = format("%s-%s", var.environment, "otel-config")
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "otel_parameter_value" {
  secret      = google_secret_manager_secret.otel_parameter.id
  secret_data = file("${path.module}/files/config.yaml")
}

resource "google_project_iam_member" "tvs_secret_accessor_iam" {
  project     = var.project_id
  role        = "roles/secretmanager.secretAccessor"
  member      = "serviceAccount:${var.tvs_service_account}"
}

resource "google_secret_manager_secret_iam_member" "member" {
  project     = var.project_id
  secret_id = google_secret_manager_secret.otel_parameter.secret_id
  role = "roles/secretmanager.secretAccessor"
  member      = "serviceAccount:${var.tvs_service_account}"
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
        "--instance_id=${var.tvs_spanner_instance_name}",
        "--database_id=${var.tvs_spanner_database_name}",
        "--coordinator_project_id=${var.coordinator_project_id}",
        "--coordinator_instance_id=${var.coordinator_spanner_instance_name}",
        "--coordinator_database_id=${var.coordinator_spanner_database_name}",
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

      env {
        name = "OTEL_EXPORTER_OTLP_ENDPOINT"
        value = "http://localhost:4317"
      }
    }
    containers {
      name = "collector"
      image = "us-docker.pkg.dev/cloud-ops-agents-artifacts/google-cloud-opentelemetry-collector/otelcol-google:0.122.1"
      args = ["--config=/etc/otelcol-google/config.yaml"]
      startup_probe {
        http_get {
          path = "/"
          port = 13133
        }
      }
      volume_mounts {
        name = "config"
        mount_path = "/etc/otelcol-google/"
      }
    }
    volumes {
      name = "config"
      secret {
        secret = google_secret_manager_secret.otel_parameter.secret_id
        items {
          path = "config.yaml"
          version = "latest"
        }
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

    service_account = var.tvs_service_account
  }

  custom_audiences = var.tvs_custom_audiences
}
