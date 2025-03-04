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

# Network Endpoint Group to route to Cloud Run
resource "google_compute_region_network_endpoint_group" "tvs_cloud_run" {
  count = var.enable_domain_management ? 1 : 0

  project               = var.project_id
  name                  = "${var.environment}-${var.region}-tvs-cloud-run"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_v2_service.tvs.name
  }
}

# Backend service that groups network endpoint groups to Cloud Run for Load
# Balancer to use.
resource "google_compute_backend_service" "tvs_cloud_run" {
  count = var.enable_domain_management ? 1 : 0

  project     = var.project_id
  name        = "${var.environment}-tvs-cloud-run"
  description = "Load balancer backend service for Trusted Verification services (TVS)."

  enable_cdn = false
  protocol   = "HTTP2"

  backend {
    description = var.environment
    group       = google_compute_region_network_endpoint_group.tvs_cloud_run[0].id
  }

  log_config {
    enable = true
  }
}

# URL Map creates Load balancer to Cloud Run
resource "google_compute_url_map" "tvs_cloud_run" {
  count = var.enable_domain_management ? 1 : 0

  project         = var.project_id
  name            = "${var.environment}-tvs-cloud-run"
  default_service = google_compute_backend_service.tvs_cloud_run[0].id
}

# Proxy to loadbalancer for Cloud Run. HTTPS with custom domain
resource "google_compute_target_https_proxy" "tvs_cloud_run" {
  count = var.enable_domain_management ? 1 : 0

  project = var.project_id
  name    = "${var.environment}-tvs-cloud-run"
  url_map = google_compute_url_map.tvs_cloud_run[0].id

  ssl_certificates = [
    google_compute_managed_ssl_certificate.tvs_loadbalancer[0].id
  ]
}

# Reserve IP address.
resource "google_compute_global_address" "tvs_ip_address" {
  count = var.enable_domain_management ? 1 : 0

  project = var.project_id
  name    = "${var.environment}-tvs-ip-address"
}

# Map IP address and loadbalancer proxy to Cloud Run
resource "google_compute_global_forwarding_rule" "tvs_cloud_run" {
  count = var.enable_domain_management ? 1 : 0

  project    = var.project_id
  name       = "${var.environment}-tvs-cloud-run"
  ip_address = google_compute_global_address.tvs_ip_address[0].address
  port_range = "443"

  target = (
    google_compute_target_https_proxy.tvs_cloud_run[0].id
  )
}

# Creates SSL cert for given domain. Terraform does not wait for SSL cert to be provisioned before the `apply` operation
# succeeds. As long as the hosted zone exists, it can take up to 20 mins for the cert to be provisioned.
# See console for status: https://console.cloud.google.com/loadbalancing/advanced/sslCertificates/list
# Note: even if status of cert becomes 'Active', it can still take around 10 mins for requests to the domain to work.
resource "google_compute_managed_ssl_certificate" "tvs_loadbalancer" {
  count   = var.enable_domain_management ? 1 : 0
  project = var.project_id
  name    = "${var.environment}-tvs-cert"

  managed {
    domains = [var.tvs_domain]
  }
}
